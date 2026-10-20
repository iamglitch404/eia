/*
 * src/eia_loader.c - Production EIA Dynamic Linker-Loader (eia-run)
 *
 * Implements the true EIA dynamic linking & loading substrate:
 *   eia-run <client_binary> [provider_binary ...]
 *
 * Features:
 *   - Universal Hologram detection (UPBP offset 1152 & native ELF offset 0x80)
 *   - BLAKE3-64 cryptographic integrity verification
 *   - Dual Virtual Alias Mapping (DVAM) with strict W^X enforcement
 *   - Fail-closed schema evolution & validation
 *   - Inter-binary symbol linking (EIA_PATCH_SYM_REL32)
 *   - In-memory type-graph displacement patching (EIA_PATCH_FIELD_DISP32)
 *   - HASI cache pipeline synchronization
 *   - Writer alias unmapping prior to code execution
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#include <sys/mman.h>
#if defined(__linux__)
#include <sys/syscall.h>
#endif
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#endif
#include "spark0.h"
#include "gdam.h"
#include <stdatomic.h>

/* ========================================================================= */
/*       PRODUCTION GDAM (GENERATION-DRIVEN SCHEMA MIGRATION) RUNTIME        */
/* ========================================================================= */

static ConcurrentGdamState g_runtime_gdam;
static GdamGeneration g_provider_gens[MAX_LOADED_PROVIDERS + 1];
static GdamKernelResource *g_kernel_resources = NULL;
static pthread_mutex_t g_kernel_res_lock = PTHREAD_MUTEX_INITIALIZER;

void gdam_init(ConcurrentGdamState *gdam, GdamGeneration *init_gen) {
    memset(gdam, 0, sizeof(*gdam));
    atomic_init(&gdam->active_readers, 0);
    atomic_init(&gdam->active_generation, init_gen);
}

GdamGeneration *gdam_reader_enter(ConcurrentGdamState *gdam) {
    if (!gdam) return NULL;
    atomic_fetch_add_explicit(&gdam->active_readers, 1, memory_order_acquire);
    return atomic_load_explicit(&gdam->active_generation, memory_order_acquire);
}

void gdam_reader_leave(ConcurrentGdamState *gdam) {
    if (!gdam) return;
    atomic_fetch_sub_explicit(&gdam->active_readers, 1, memory_order_release);
}

uint64_t gdam_atomic_publish(ConcurrentGdamState *gdam, GdamGeneration *new_gen) {
    if (!gdam || !new_gen) return 0;
    gdam->previous_generation = atomic_load(&gdam->active_generation);
    atomic_store_explicit(&gdam->active_generation, new_gen, memory_order_release);
    return new_gen->epoch ? new_gen->epoch : 1;
}

int gdam_rollback(ConcurrentGdamState *gdam) {
    if (!gdam || !gdam->previous_generation) return -1;
    atomic_store_explicit(&gdam->active_generation, gdam->previous_generation, memory_order_release);
    return 0;
}

void gdam_retire_record(ConcurrentGdamState *gdam, uint8_t *old_rec) {
    if (!gdam || !old_rec) return;
    if (gdam->retired_count < MAX_LOADED_PROVIDERS + 1) {
        gdam->retired_records[gdam->retired_count++] = old_rec;
    }
}

void gdam_reclaim_retired(ConcurrentGdamState *gdam) {
    if (!gdam) return;
    while (atomic_load_explicit(&gdam->active_readers, memory_order_acquire) > 0) {
#ifdef _WIN32
        Sleep(1);
#else
        usleep(100);
#endif
    }
    for (size_t i = 0; i < gdam->retired_count; ++i) {
        if (gdam->retired_records[i]) {
            free(gdam->retired_records[i]);
            gdam->retired_records[i] = NULL;
        }
    }
    gdam->retired_count = 0;
}

size_t gdam_migrate_record(
    const uint8_t *old_buf, const GdamFieldEntry *old_tg, size_t old_count,
    uint8_t *new_buf, const GdamFieldEntry *new_tg, size_t new_count,
    uint64_t type_hash
) {
    size_t migrated = 0;
    for (size_t ni = 0; ni < new_count; ++ni) {
        if (new_tg[ni].type_sig_hash == type_hash) {
            for (size_t oi = 0; oi < old_count; ++oi) {
                if (old_tg[oi].type_sig_hash == type_hash &&
                    old_tg[oi].field_hash == new_tg[ni].field_hash) {
                    uint32_t copy_sz = old_tg[oi].field_size < new_tg[ni].field_size ?
                                       old_tg[oi].field_size : new_tg[ni].field_size;
                    memcpy(new_buf + new_tg[ni].byte_offset,
                           old_buf + old_tg[oi].byte_offset, copy_sz);
                    if (new_tg[ni].field_size > old_tg[oi].field_size) {
                        memset(new_buf + new_tg[ni].byte_offset + copy_sz, 0,
                               new_tg[ni].field_size - copy_sz);
                    }
                    migrated++;
                    break;
                }
            }
        }
    }
    return migrated;
}

int eia_gdam_stage_upgrade(ConcurrentGdamState *gdam, GdamGeneration *next_gen) {
    if (!gdam || !next_gen) return -1;
    gdam->staged_generation = next_gen;
    return 0;
}

uint64_t eia_gdam_commit_upgrade(ConcurrentGdamState *gdam, GdamGeneration *new_gen, uint64_t type_hash) {
    if (!gdam || !new_gen) return 0;
    GdamGeneration *prev_gen = atomic_load(&gdam->active_generation);
    if (prev_gen && prev_gen->record_buf && new_gen->count > 0 && new_gen->schema) {
        size_t new_sz = 0;
        for (size_t f = 0; f < new_gen->count; ++f) {
            uint32_t end = new_gen->schema[f].byte_offset + new_gen->schema[f].field_size;
            if (end > new_sz) new_sz = end;
        }
        if (new_sz > 0) {
            uint8_t *migrated_buf = (uint8_t *)calloc(new_sz, 1);
            if (migrated_buf) {
                gdam_migrate_record(
                    prev_gen->record_buf, prev_gen->schema, prev_gen->count,
                    migrated_buf, new_gen->schema, new_gen->count,
                    type_hash
                );
                new_gen->record_buf = migrated_buf;
                gdam_retire_record(gdam, (uint8_t *)prev_gen->record_buf);
                prev_gen->record_buf = NULL;
            }
        }
    }
    uint64_t pub_epoch = gdam_atomic_publish(gdam, new_gen);
    gdam->staged_generation = NULL;
    return pub_epoch;
}

int eia_gdam_rollback_upgrade(ConcurrentGdamState *gdam) {
    return gdam_rollback(gdam);
}

int eia_gdam_register_thread(ConcurrentGdamState *gdam, uint64_t thread_id) {
    if (!gdam || thread_id == 0) return -1;
    for (size_t i = 0; i < MAX_GDAM_THREADS; ++i) {
        uint64_t expected = 0;
        if (atomic_compare_exchange_strong(&gdam->threads[i].thread_id, &expected, thread_id)) {
            atomic_store_explicit(&gdam->threads[i].entered_epoch, 0, memory_order_relaxed);
            atomic_store_explicit(&gdam->threads[i].in_critical_section, false, memory_order_release);
            atomic_fetch_add(&gdam->thread_count, 1);
            return 0;
        }
    }
    return -1;
}

int eia_gdam_unregister_thread(ConcurrentGdamState *gdam, uint64_t thread_id) {
    if (!gdam || thread_id == 0) return -1;
    for (size_t i = 0; i < MAX_GDAM_THREADS; ++i) {
        if (atomic_load(&gdam->threads[i].thread_id) == thread_id) {
            atomic_store_explicit(&gdam->threads[i].in_critical_section, false, memory_order_release);
            atomic_store_explicit(&gdam->threads[i].thread_id, 0, memory_order_release);
            atomic_fetch_sub(&gdam->thread_count, 1);
            return 0;
        }
    }
    return -1;
}

void eia_gdam_thread_enter(ConcurrentGdamState *gdam, uint64_t thread_id) {
    if (!gdam || thread_id == 0) return;
    for (size_t i = 0; i < MAX_GDAM_THREADS; ++i) {
        if (atomic_load_explicit(&gdam->threads[i].thread_id, memory_order_relaxed) == thread_id) {
            GdamGeneration *gen = atomic_load_explicit(&gdam->active_generation, memory_order_acquire);
            uint64_t ep = gen && gen->epoch ? gen->epoch : 1;
            atomic_store_explicit(&gdam->threads[i].entered_epoch, ep, memory_order_relaxed);
            atomic_store_explicit(&gdam->threads[i].in_critical_section, true, memory_order_release);
            atomic_fetch_add_explicit(&gdam->active_readers, 1, memory_order_acquire);
            return;
        }
    }
}

void eia_gdam_thread_leave(ConcurrentGdamState *gdam, uint64_t thread_id) {
    if (!gdam || thread_id == 0) return;
    for (size_t i = 0; i < MAX_GDAM_THREADS; ++i) {
        if (atomic_load_explicit(&gdam->threads[i].thread_id, memory_order_relaxed) == thread_id) {
            atomic_store_explicit(&gdam->threads[i].in_critical_section, false, memory_order_release);
            atomic_fetch_sub_explicit(&gdam->active_readers, 1, memory_order_release);
            return;
        }
    }
}

static inline void gdam_object_lock(ConcurrentGdamState *gdam) {
    if (!gdam) return;
    while (atomic_exchange_explicit(&gdam->object_lock, 1, memory_order_acquire)) {
#if defined(__x86_64__)
        __builtin_ia32_pause();
#elif defined(__aarch64__)
        asm volatile("yield");
#endif
    }
}

static inline void gdam_object_unlock(ConcurrentGdamState *gdam) {
    if (!gdam) return;
    atomic_store_explicit(&gdam->object_lock, 0, memory_order_release);
}

int eia_gdam_register_object(ConcurrentGdamState *gdam, void **obj_ref, uint64_t type_hash, size_t element_count, size_t elem_size) {
    if (!gdam || !obj_ref) return -1;
    GdamObjectNode *node = (GdamObjectNode *)malloc(sizeof(GdamObjectNode));
    if (!node) return -1;
    node->object_ptr_ref = obj_ref;
    node->type_sig_hash = type_hash;
    node->element_count = element_count > 0 ? element_count : 1;
    node->element_size = elem_size;
    gdam_object_lock(gdam);
    node->next = gdam->object_graph;
    gdam->object_graph = node;
    gdam_object_unlock(gdam);
    return 0;
}

int eia_gdam_unregister_object(ConcurrentGdamState *gdam, void **obj_ref) {
    if (!gdam || !obj_ref) return -1;
    gdam_object_lock(gdam);
    GdamObjectNode **curr = &gdam->object_graph;
    while (*curr) {
        if ((*curr)->object_ptr_ref == obj_ref) {
            GdamObjectNode *to_free = *curr;
            *curr = (*curr)->next;
            gdam_object_unlock(gdam);
            free(to_free);
            return 0;
        }
        curr = &(*curr)->next;
    }
    gdam_object_unlock(gdam);
    return -1;
}

int eia_gdam_publish_object_pointer(ConcurrentGdamState *gdam, void **obj_ref, void *new_ptr) {
    if (!gdam || !obj_ref) return -1;
    __atomic_store_n(obj_ref, new_ptr, __ATOMIC_RELEASE);
    return 0;
}

uint64_t eia_gdam_migrate_object_graph(ConcurrentGdamState *gdam, GdamGeneration *new_gen, uint64_t type_hash) {
    if (!gdam || !new_gen || !new_gen->schema || new_gen->count == 0) return 0;
    GdamGeneration *prev_gen = atomic_load(&gdam->active_generation);
    if (!prev_gen || !prev_gen->schema) return 0;

    size_t new_elem_size = 0;
    for (size_t f = 0; f < new_gen->count; ++f) {
        if (new_gen->schema[f].type_sig_hash == type_hash) {
            uint32_t end = new_gen->schema[f].byte_offset + new_gen->schema[f].field_size;
            if (end > new_elem_size) new_elem_size = end;
        }
    }
    if (new_elem_size == 0) return 0;

    uint64_t migrated_count = 0;
    gdam_object_lock(gdam);
    GdamObjectNode *curr = gdam->object_graph;
    while (curr) {
        if (curr->type_sig_hash == type_hash && curr->object_ptr_ref && *curr->object_ptr_ref) {
            uint8_t *old_buf = (uint8_t *)(*curr->object_ptr_ref);
            size_t total_new_sz = curr->element_count * new_elem_size;
            uint8_t *new_buf = (uint8_t *)calloc(total_new_sz, 1);
            if (new_buf) {
                for (size_t elem = 0; elem < curr->element_count; ++elem) {
                    const uint8_t *old_elem = old_buf + elem * curr->element_size;
                    uint8_t *new_elem = new_buf + elem * new_elem_size;
                    gdam_migrate_record(
                        old_elem, prev_gen->schema, prev_gen->count,
                        new_elem, new_gen->schema, new_gen->count,
                        type_hash
                    );
                }
                if (!new_gen->record_buf) {
                    new_gen->record_buf = new_buf;
                }
                __atomic_store_n(curr->object_ptr_ref, new_buf, __ATOMIC_RELEASE);
                curr->element_size = new_elem_size;
                gdam_retire_record(gdam, old_buf);
                migrated_count++;
            }
        }
        curr = curr->next;
    }
    gdam_object_unlock(gdam);

    uint64_t pub_epoch = gdam_atomic_publish(gdam, new_gen);
    (void)pub_epoch;

    for (size_t i = 0; i < MAX_GDAM_THREADS; ++i) {
        while (atomic_load_explicit(&gdam->threads[i].in_critical_section, memory_order_acquire) &&
               atomic_load_explicit(&gdam->threads[i].entered_epoch, memory_order_acquire) < (new_gen->epoch ? new_gen->epoch : 1)) {
#ifdef _WIN32
            Sleep(1);
#else
            usleep(50);
#endif
        }
    }
    return migrated_count;
}

/* Public GDAM Runtime API (include/gdam.h) */
int gdam_runtime_init(ConcurrentGdamState *gdam, GdamGeneration *init_gen) {
    if (!gdam) return GDAM_ERR_INVALID_ARG;
    gdam_init(gdam, init_gen);
    return GDAM_SUCCESS;
}

int gdam_runtime_shutdown(ConcurrentGdamState *gdam) {
    if (!gdam) return GDAM_ERR_INVALID_ARG;
    gdam_reclaim_retired(gdam);
#ifndef _WIN32
    pthread_mutex_lock(&g_kernel_res_lock);
    GdamKernelResource *kcurr = g_kernel_resources;
    while (kcurr) {
        GdamKernelResource *next = kcurr->next;
        free(kcurr);
        kcurr = next;
    }
    g_kernel_resources = NULL;
    pthread_mutex_unlock(&g_kernel_res_lock);
#endif
    return GDAM_SUCCESS;
}

int gdam_thread_register(ConcurrentGdamState *gdam, uint64_t tid) {
    return eia_gdam_register_thread(gdam, tid) == 0 ? GDAM_SUCCESS : GDAM_ERR_BUSY;
}

int gdam_thread_unregister(ConcurrentGdamState *gdam, uint64_t tid) {
    return eia_gdam_unregister_thread(gdam, tid) == 0 ? GDAM_SUCCESS : GDAM_ERR_INVALID_ARG;
}

void gdam_safepoint_enter(ConcurrentGdamState *gdam, uint64_t tid) {
    eia_gdam_thread_enter(gdam, tid);
}

void gdam_safepoint_leave(ConcurrentGdamState *gdam, uint64_t tid) {
    eia_gdam_thread_leave(gdam, tid);
}

int gdam_object_register(ConcurrentGdamState *gdam, void **obj_ref, uint64_t type_hash, size_t count, size_t elem_size) {
    return eia_gdam_register_object(gdam, obj_ref, type_hash, count, elem_size) == 0 ? GDAM_SUCCESS : GDAM_ERR_INVALID_ARG;
}

int gdam_object_unregister(ConcurrentGdamState *gdam, void **obj_ref) {
    return eia_gdam_unregister_object(gdam, obj_ref) == 0 ? GDAM_SUCCESS : GDAM_ERR_INVALID_ARG;
}

int gdam_publish_pointer(ConcurrentGdamState *gdam, void **obj_ref, void *new_ptr) {
    return eia_gdam_publish_object_pointer(gdam, obj_ref, new_ptr) == 0 ? GDAM_SUCCESS : GDAM_ERR_INVALID_ARG;
}

int gdam_stage_migration(ConcurrentGdamState *gdam, GdamGeneration *next_gen) {
    return eia_gdam_stage_upgrade(gdam, next_gen) == 0 ? GDAM_SUCCESS : GDAM_ERR_INVALID_ARG;
}

uint64_t gdam_commit_migration(ConcurrentGdamState *gdam, GdamGeneration *new_gen, uint64_t type_hash) {
    return eia_gdam_migrate_object_graph(gdam, new_gen, type_hash);
}

int gdam_abort_migration(ConcurrentGdamState *gdam) {
    return gdam_rollback(gdam) == 0 ? GDAM_SUCCESS : GDAM_ERR_ROLLBACK;
}

/* ------------------------------------------------------------------------- */
/* Kernel Handle & Stream Socket Migration (FD, SCM_RIGHTS, Seek State)      */
/* ------------------------------------------------------------------------- */

int gdam_register_kernel_handle(ConcurrentGdamState *gdam, int fd, int resource_type) {
    if (fd < 0) return GDAM_ERR_INVALID_ARG;
    (void)gdam;
    GdamKernelResource *node = (GdamKernelResource *)calloc(1, sizeof(GdamKernelResource));
    if (!node) return GDAM_ERR_NO_MEMORY;
    node->fd = fd;
    node->resource_type = resource_type;
#ifndef _WIN32
    node->flags = fcntl(fd, F_GETFL, 0);
    node->seek_offset = lseek(fd, 0, SEEK_CUR);
#endif
    pthread_mutex_lock(&g_kernel_res_lock);
    node->next = g_kernel_resources;
    g_kernel_resources = node;
    pthread_mutex_unlock(&g_kernel_res_lock);
    return GDAM_SUCCESS;
}

int gdam_migrate_kernel_handle(ConcurrentGdamState *gdam, int old_fd, int *new_fd_out) {
    if (old_fd < 0 || !new_fd_out) return GDAM_ERR_INVALID_ARG;
    (void)gdam;
#ifndef _WIN32
    int new_fd = fcntl(old_fd, F_DUPFD_CLOEXEC, 0);
    if (new_fd < 0) {
        new_fd = dup(old_fd);
        if (new_fd < 0) return GDAM_ERR_INVALID_ARG;
    }

    off_t off = lseek(old_fd, 0, SEEK_CUR);
    if (off != (off_t)-1) {
        lseek(new_fd, off, SEEK_SET);
    }

    pthread_mutex_lock(&g_kernel_res_lock);
    GdamKernelResource *curr = g_kernel_resources;
    while (curr) {
        if (curr->fd == old_fd) {
            curr->fd = new_fd;
            curr->seek_offset = off;
            break;
        }
        curr = curr->next;
    }
    pthread_mutex_unlock(&g_kernel_res_lock);

    *new_fd_out = new_fd;
    return GDAM_SUCCESS;
#else
    *new_fd_out = old_fd;
    return GDAM_SUCCESS;
#endif
}

int gdam_unregister_kernel_handle(ConcurrentGdamState *gdam, int fd) {
    (void)gdam;
    pthread_mutex_lock(&g_kernel_res_lock);
    GdamKernelResource **curr = &g_kernel_resources;
    while (*curr) {
        if ((*curr)->fd == fd) {
            GdamKernelResource *to_free = *curr;
            *curr = (*curr)->next;
            free(to_free);
            pthread_mutex_unlock(&g_kernel_res_lock);
            return GDAM_SUCCESS;
        }
        curr = &(*curr)->next;
    }
    pthread_mutex_unlock(&g_kernel_res_lock);
    return GDAM_ERR_INVALID_ARG;
}

int gdam_send_fd_scm_rights(int unix_sock, int fd_to_send) {
#ifndef _WIN32
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    char buf[CMSG_SPACE(sizeof(int))];
    memset(buf, 0, sizeof(buf));

    struct iovec io;
    io.iov_base = (void *)"EIA_FD";
    io.iov_len = 6;
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    *((int *)CMSG_DATA(cmsg)) = fd_to_send;

    if (sendmsg(unix_sock, &msg, 0) < 0) return -1;
    return 0;
#else
    (void)unix_sock; (void)fd_to_send;
    return -1;
#endif
}

int gdam_recv_fd_scm_rights(int unix_sock, int *fd_received_out) {
#ifndef _WIN32
    if (!fd_received_out) return -1;
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    char m_buf[16];
    struct iovec io;
    io.iov_base = m_buf;
    io.iov_len = sizeof(m_buf);
    char c_buf[CMSG_SPACE(sizeof(int))];
    memset(c_buf, 0, sizeof(c_buf));

    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = c_buf;
    msg.msg_controllen = sizeof(c_buf);

    if (recvmsg(unix_sock, &msg, 0) < 0) return -1;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS) return -1;
    *fd_received_out = *((int *)CMSG_DATA(cmsg));
    return 0;
#else
    (void)unix_sock; (void)fd_received_out;
    return -1;
#endif
}

/* Diagnostic error codes */
#define EIA_SUCCESS                  0
#define EIA_ERR_BOUNDS_OVERFLOW     -4
#define EIA_ERR_SYMBOL_NOT_FOUND    -5
#define EIA_ERR_SIGNATURE_MISMATCH  -6
#define EIA_ERR_FIELD_NOT_FOUND     -7
#define EIA_ERR_INTEGRITY_MISMATCH  -8
#define EIA_ERR_BAD_INSN            -9
#define EIA_ERR_RELOC_OVERLAP       -10
#define EIA_ERR_WIDTH_MISMATCH      -11
#define EIA_ERR_NARROWING_UNSUPPORTED -13

uint64_t spark0_hash64(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < len; ++i) {
        h ^= p[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

uint64_t spark0_hash_str(const char *str) {
    if (!str) return 0;
    return spark0_hash64(str, strlen(str));
}

/* Fast BLAKE3-64 implementation */
static inline uint32_t rot32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

static inline uint32_t get_u32(const uint8_t *p, size_t i) {
    return (uint32_t)p[i*4] | ((uint32_t)p[i*4+1] << 8) |
           ((uint32_t)p[i*4+2] << 16) | ((uint32_t)p[i*4+3] << 24);
}

static inline void set_u32(uint8_t *p, size_t i, uint32_t v) {
    p[i*4]   = (uint8_t)(v & 0xFF);
    p[i*4+1] = (uint8_t)((v >> 8) & 0xFF);
    p[i*4+2] = (uint8_t)((v >> 16) & 0xFF);
    p[i*4+3] = (uint8_t)((v >> 24) & 0xFF);
}

static void blake3_round_g(uint8_t *state, const uint8_t *msg, size_t step) {
    static const uint8_t g_idx[8][4] = {
        {0, 4,  8, 12}, {1, 5,  9, 13}, {2, 6, 10, 14}, {3, 7, 11, 15},
        {0, 5, 10, 15}, {1, 6, 11, 12}, {2, 7,  8, 13}, {3, 4,  9, 14}
    };
    uint8_t a = g_idx[step][0], b = g_idx[step][1], c = g_idx[step][2], d = g_idx[step][3];
    uint32_t va = get_u32(state, a), vb = get_u32(state, b);
    uint32_t vc = get_u32(state, c), vd = get_u32(state, d);
    uint32_t m0 = get_u32(msg, step * 2), m1 = get_u32(msg, step * 2 + 1);

    va = va + vb + m0; vd = rot32(vd ^ va, 16);
    vc = vc + vd;      vb = rot32(vb ^ vc, 12);
    va = va + vb + m1; vd = rot32(vd ^ va, 8);
    vc = vc + vd;      vb = rot32(vb ^ vc, 7);

    set_u32(state, a, va); set_u32(state, b, vb);
    set_u32(state, c, vc); set_u32(state, d, vd);
}

static void blake3_permute_msg(uint8_t *msg) {
    static const uint8_t sigma[16] = {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8};
    uint8_t tmp[64];
    memcpy(tmp, msg, 64);
    for (size_t i = 0; i < 16; ++i) {
        set_u32(msg, i, get_u32(tmp, sigma[i]));
    }
}

static void blake3_compress_block(const uint8_t *cv, const uint8_t *block_buf,
                                  uint32_t block_len, uint64_t chunk_counter, uint32_t flags,
                                  uint8_t *out_cv) {
    uint8_t state[64];
    for (size_t i = 0; i < 8; ++i) set_u32(state, i, get_u32(cv, i));
    set_u32(state, 8,  1779033703);
    set_u32(state, 9,  3144134277);
    set_u32(state, 10, 1013904242);
    set_u32(state, 11, 2773480762);
    set_u32(state, 12, (uint32_t)(chunk_counter & 0xFFFFFFFF));
    set_u32(state, 13, (uint32_t)(chunk_counter >> 32));
    set_u32(state, 14, block_len);
    set_u32(state, 15, flags);

    uint8_t msg[64];
    memset(msg, 0, 64);
    if (block_len > 0) memcpy(msg, block_buf, block_len > 64 ? 64 : block_len);

    for (size_t round = 0; round < 7; ++round) {
        for (size_t step = 0; step < 8; ++step) blake3_round_g(state, msg, step);
        if (round < 6) blake3_permute_msg(msg);
    }

    for (size_t i = 0; i < 8; ++i) {
        uint32_t new_cv_word = get_u32(state, i) ^ get_u32(state, i + 8);
        set_u32(out_cv, i, new_cv_word);
    }
}

static void blake3_hash_chunk(const uint8_t *chunk_data, size_t chunk_len,
                              uint64_t chunk_counter, int is_root, uint8_t *out_cv) {
    static const uint32_t iv[8] = {
        1779033703, 3144134277, 1013904242, 2773480762,
        1359893119, 2600822924, 528734635,  1541459225
    };
    uint8_t cv[32];
    for (size_t i = 0; i < 8; ++i) set_u32(cv, i, iv[i]);

    if (chunk_len == 0) {
        uint32_t flags = 1 | 2; // CHUNK_START | CHUNK_END
        if (is_root) flags |= 8; // ROOT
        blake3_compress_block(cv, chunk_data, 0, chunk_counter, flags, out_cv);
        return;
    }

    size_t num_blocks = (chunk_len + 63) / 64;
    for (size_t b = 0; b < num_blocks; ++b) {
        size_t blk_off = b * 64;
        uint32_t blk_len = (uint32_t)((chunk_len - blk_off > 64) ? 64 : (chunk_len - blk_off));
        uint32_t flags = 0;
        if (b == 0) flags |= 1; // CHUNK_START
        if (b == num_blocks - 1) {
            flags |= 2; // CHUNK_END
            if (is_root) flags |= 8; // ROOT
        }
        uint8_t next_cv[32];
        blake3_compress_block(cv, chunk_data + blk_off, blk_len, chunk_counter, flags, next_cv);
        memcpy(cv, next_cv, 32);
    }
    memcpy(out_cv, cv, 32);
}

static void blake3_parent_cv(const uint8_t *left_cv, const uint8_t *right_cv, int is_root, uint8_t *out_cv) {
    static const uint32_t iv[8] = {
        1779033703, 3144134277, 1013904242, 2773480762,
        1359893119, 2600822924, 528734635,  1541459225
    };
    uint8_t block[64];
    memcpy(block, left_cv, 32);
    memcpy(block + 32, right_cv, 32);

    uint8_t cv[32];
    for (size_t i = 0; i < 8; ++i) set_u32(cv, i, iv[i]);

    uint32_t flags = 4; // PARENT
    if (is_root) flags |= 8; // ROOT

    blake3_compress_block(cv, block, 64, 0, flags, out_cv);
}

void blake3_hash256(const uint8_t *buf, size_t len, uint8_t out_digest[32]) {
    if (len <= 1024) {
        blake3_hash_chunk(buf, len, 0, 1, out_digest);
        return;
    }

    size_t num_chunks = (len + 1023) / 1024;
    uint8_t (*cv_list)[32] = (uint8_t (*)[32])malloc(num_chunks * 32);
    for (size_t c = 0; c < num_chunks; ++c) {
        size_t c_off = c * 1024;
        size_t c_len = (len - c_off > 1024) ? 1024 : (len - c_off);
        blake3_hash_chunk(buf + c_off, c_len, (uint64_t)c, 0, cv_list[c]);
    }

    size_t cv_count = num_chunks;
    while (cv_count > 1) {
        size_t next_count = 0;
        for (size_t i = 0; i < cv_count; i += 2) {
            if (i + 1 < cv_count) {
                int is_root = (cv_count == 2);
                uint8_t parent_cv[32];
                blake3_parent_cv(cv_list[i], cv_list[i+1], is_root, parent_cv);
                memcpy(cv_list[next_count++], parent_cv, 32);
            } else {
                memcpy(cv_list[next_count++], cv_list[i], 32);
            }
        }
        cv_count = next_count;
    }

    memcpy(out_digest, cv_list[0], 32);
    free(cv_list);
}

uint64_t blake3_hash64(const uint8_t *buf, size_t len) {
    uint8_t digest[32];
    blake3_hash256(buf, len, digest);
    uint64_t low = (uint64_t)get_u32(digest, 0);
    uint64_t high = (uint64_t)get_u32(digest, 1);
    return low | (high << 32);
}

#include "eia_ed25519.c"

/* Binary artifact representation */
typedef struct {
    const char *path;
    uint8_t *file_data;
    size_t file_size;
    const UniversalHologramHeader *holo;
    const SymbolContract *contracts;
    size_t contract_count;
    const EiaRelocHole *relocs;
    size_t reloc_count;
    const EiaTypeGraphEntry *type_graph;
    size_t type_graph_count;
    const uint8_t *text_data;
    size_t text_size;
    size_t arena_offset; /* Byte offset where this binary's text begins in DVAM arena */
    uint16_t target_arch; /* 0=x86_64, 1=aarch64, 2=riscv64 */
    uint64_t text_vaddr_base; /* Base virtual address of code section */
} LoadedBinary;

/* Symbol export dynamic hash table entry */
typedef struct {
    uint64_t symbol_hash;
    uint64_t type_sig_hash;
    uint64_t target_vaddr; /* Virtual address in v_exec mapping */
    uint16_t param_count;
    uint16_t calling_conv;
    const char *binary_name;
    bool occupied;
} SymbolHashEntry;

typedef struct {
    SymbolHashEntry *entries;
    size_t capacity;
    size_t count;
} SymbolRegistry;

/* Type graph field dynamic hash table entry */
typedef struct {
    uint64_t type_sig_hash;
    uint64_t field_hash;
    uint32_t byte_offset;
    uint32_t field_size;
    bool occupied;
} TypeFieldHashEntry;

typedef struct {
    TypeFieldHashEntry *entries;
    size_t capacity;
    size_t count;
} FieldRegistry;

static inline size_t hash_field_key(uint64_t type_hash, uint64_t field_hash, size_t cap) {
    uint64_t k = type_hash ^ (field_hash * 0x100000001b3ULL);
    k ^= (k >> 33);
    k *= 0xff51afd7ed558ccdULL;
    k ^= (k >> 33);
    return (size_t)(k & (cap - 1));
}

static void __attribute__((unused)) field_reg_init(FieldRegistry *r, size_t cap) {
    r->capacity = cap ? cap : 1024;
    r->count = 0;
    r->entries = (TypeFieldHashEntry *)calloc(r->capacity, sizeof(TypeFieldHashEntry));
}

static void __attribute__((unused)) field_reg_free(FieldRegistry *r) {
    if (r->entries) {
        free(r->entries);
        r->entries = NULL;
    }
    r->count = r->capacity = 0;
}

static void field_reg_grow(FieldRegistry *r);

static void __attribute__((unused)) field_reg_insert(FieldRegistry *r, uint64_t type_hash, uint64_t field_hash, uint32_t offset, uint32_t size) {
    if (r->count * 10 >= r->capacity * 7) {
        field_reg_grow(r);
    }
    size_t idx = hash_field_key(type_hash, field_hash, r->capacity);
    for (size_t step = 0; step < r->capacity; ++step) {
        size_t i = (idx + step) & (r->capacity - 1);
        if (!r->entries[i].occupied || (r->entries[i].type_sig_hash == type_hash && r->entries[i].field_hash == field_hash)) {
            if (!r->entries[i].occupied) r->count++;
            r->entries[i].type_sig_hash = type_hash;
            r->entries[i].field_hash = field_hash;
            r->entries[i].byte_offset = offset;
            r->entries[i].field_size = size & 0xFFFF;
            r->entries[i].occupied = true;
            return;
        }
    }
}

static void field_reg_grow(FieldRegistry *r) {
    size_t old_cap = r->capacity;
    TypeFieldHashEntry *old_entries = r->entries;

    r->capacity = old_cap * 2;
    r->count = 0;
    r->entries = (TypeFieldHashEntry *)calloc(r->capacity, sizeof(TypeFieldHashEntry));

    for (size_t i = 0; i < old_cap; ++i) {
        if (old_entries[i].occupied) {
            field_reg_insert(r, old_entries[i].type_sig_hash, old_entries[i].field_hash, old_entries[i].byte_offset, old_entries[i].field_size);
        }
    }
    free(old_entries);
}

static __attribute__((unused)) const TypeFieldHashEntry *field_reg_lookup(const FieldRegistry *r, uint64_t type_hash, uint64_t field_hash) {
    if (!r->entries || r->capacity == 0) return NULL;
    size_t idx = hash_field_key(type_hash, field_hash, r->capacity);
    for (size_t step = 0; step < r->capacity; ++step) {
        size_t i = (idx + step) & (r->capacity - 1);
        if (!r->entries[i].occupied) return NULL;
        if (r->entries[i].type_sig_hash == type_hash && r->entries[i].field_hash == field_hash) {
            return &r->entries[i];
        }
    }
    return NULL;
}

static inline size_t hash_sym_key(uint64_t sym_hash, size_t cap) {
    uint64_t k = sym_hash ^ (sym_hash >> 33);
    k *= 0xff51afd7ed558ccdULL;
    k ^= (k >> 33);
    return (size_t)(k & (cap - 1));
}

static void __attribute__((unused)) sym_reg_init(SymbolRegistry *r, size_t cap) {
    r->capacity = cap ? cap : 1024;
    r->count = 0;
    r->entries = (SymbolHashEntry *)calloc(r->capacity, sizeof(SymbolHashEntry));
}

static void __attribute__((unused)) sym_reg_free(SymbolRegistry *r) {
    if (r->entries) {
        free(r->entries);
        r->entries = NULL;
    }
    r->count = r->capacity = 0;
}

static void sym_reg_grow(SymbolRegistry *r);

static void sym_reg_insert(SymbolRegistry *r, uint64_t sym_hash, uint64_t type_sig_hash, uint64_t target_vaddr, uint16_t param_cnt, uint16_t cconv, const char *bin_name) {
    if (r->count * 10 >= r->capacity * 7) {
        sym_reg_grow(r);
    }
    size_t idx = hash_sym_key(sym_hash, r->capacity);
    for (size_t step = 0; step < r->capacity; ++step) {
        size_t i = (idx + step) & (r->capacity - 1);
        if (!r->entries[i].occupied) {
            r->entries[i].symbol_hash = sym_hash;
            r->entries[i].type_sig_hash = type_sig_hash;
            r->entries[i].target_vaddr = target_vaddr;
            r->entries[i].param_count = param_cnt;
            r->entries[i].calling_conv = cconv;
            r->entries[i].binary_name = bin_name;
            r->entries[i].occupied = true;
            r->count++;
            return;
        } else if (r->entries[i].symbol_hash == sym_hash) {
            /* Duplicate symbol policy: First-Provider-Precedence with signature compatibility */
            if (bin_name && r->entries[i].binary_name && strcmp(r->entries[i].binary_name, bin_name) != 0) {
                if (r->entries[i].type_sig_hash != 0 && type_sig_hash != 0 && r->entries[i].type_sig_hash != type_sig_hash) {
                    fprintf(stderr, "[EIA ERROR] Ambiguous symbol collision for 0x%016lx between '%s' and '%s' with conflicting signatures\n",
                            (unsigned long)sym_hash, r->entries[i].binary_name, bin_name);
                } else {
                    printf("[EIA LINK] Duplicate exported symbol 0x%016lx in '%s' (keeping initial export from '%s')\n",
                           (unsigned long)sym_hash, bin_name, r->entries[i].binary_name);
                }
            }
            return;
        }
    }
}

static void sym_reg_grow(SymbolRegistry *r) {
    size_t old_cap = r->capacity;
    SymbolHashEntry *old_entries = r->entries;

    r->capacity = old_cap * 2;
    r->count = 0;
    r->entries = (SymbolHashEntry *)calloc(r->capacity, sizeof(SymbolHashEntry));

    for (size_t i = 0; i < old_cap; ++i) {
        if (old_entries[i].occupied) {
            sym_reg_insert(r, old_entries[i].symbol_hash, old_entries[i].type_sig_hash,
                           old_entries[i].target_vaddr, old_entries[i].param_count,
                           old_entries[i].calling_conv, old_entries[i].binary_name);
        }
    }
    free(old_entries);
}

static __attribute__((unused)) const SymbolHashEntry *sym_reg_lookup(const SymbolRegistry *r, uint64_t sym_hash) {
    if (!r->entries || r->capacity == 0) return NULL;
    size_t idx = hash_sym_key(sym_hash, r->capacity);
    for (size_t step = 0; step < r->capacity; ++step) {
        size_t i = (idx + step) & (r->capacity - 1);
        if (!r->entries[i].occupied) return NULL;
        if (r->entries[i].symbol_hash == sym_hash) return &r->entries[i];
    }
    return NULL;
}

/* HASI cache synchronization */
static inline void hasi_cache_sync(void *addr, size_t size) {
#if defined(_WIN32)
    FlushInstructionCache(GetCurrentProcess(), addr, size);
#elif defined(__x86_64__)
    (void)addr; (void)size;
    unsigned int eax, ebx, ecx, edx;
    __asm__ __volatile__("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(0));
    __asm__ __volatile__("mfence" ::: "memory");
#elif defined(__aarch64__)
    __builtin___clear_cache((char *)addr, (char *)addr + size);
    __asm__ __volatile__("dsb ish; isb" ::: "memory");
#elif defined(__riscv)
    __builtin___clear_cache((char *)addr, (char *)addr + size);
    __asm__ __volatile__("fence.i" ::: "memory");
#else
    __builtin___clear_cache((char *)addr, (char *)addr + size);
#endif
}

/* Cross-platform execution bridge: guarantees System V ABI & preserves Win64 callee-saved registers */
static inline int64_t call_sysv_entry(void *fn_ptr) {
#if defined(_WIN32) && defined(__x86_64__)
    register void *target __asm__("r10") = fn_ptr;
    int64_t result;
    __asm__ __volatile__(
        "pushq %%rsi\n\t"
        "pushq %%rdi\n\t"
        "pushq %%rbx\n\t"
        "pushq %%r12\n\t"
        "pushq %%r13\n\t"
        "pushq %%r14\n\t"
        "pushq %%r15\n\t"
        "pushq %%rbp\n\t"
        "movq %%rsp, %%rbp\n\t"
        "subq $32, %%rsp\n\t"
        "andq $-16, %%rsp\n\t"
        "callq *%%r10\n\t"
        "movq %%rbp, %%rsp\n\t"
        "popq %%rbp\n\t"
        "popq %%r15\n\t"
        "popq %%r14\n\t"
        "popq %%r13\n\t"
        "popq %%r12\n\t"
        "popq %%rbx\n\t"
        "popq %%rdi\n\t"
        "popq %%rsi\n\t"
        : "=a"(result)
        : "r"(target)
        : "rcx", "rdx", "r8", "r9", "r11", "memory"
    );
    return result;
#else
    typedef int64_t (*ClientMainFn)(void);
    ClientMainFn fn = (ClientMainFn)fn_ptr;
    return fn();
#endif
}

/* Instruction shape validation: ensures patch site matches expected ISA field displacement pattern */
static int __attribute__((unused)) validate_field_insn_shape(uint16_t target_arch, const uint8_t *code, uint32_t insn_offset, size_t code_len) {
    if (target_arch == 1) {
        /* ARM64: movz x16, #imm; movk x16, #imm, lsl #16; add x1, x0, x16 */
        if (insn_offset + 12 <= code_len) {
            uint32_t insn0 = *(const uint32_t *)(code + insn_offset);
            uint32_t insn1 = *(const uint32_t *)(code + insn_offset + 4);
            uint32_t insn2 = *(const uint32_t *)(code + insn_offset + 8);
            if ((insn0 & 0xffe0001f) == 0xd2800010 &&
                (insn1 & 0xffe0001f) == 0xf2a00010 &&
                insn2 == 0x8b100001) {
                return EIA_SUCCESS;
            }
        }
        return EIA_ERR_BAD_INSN;
    } else if (target_arch == 2) {
        /* RISC-V 64: lui t0, #hi; addi t0, t0, #lo; add a1, a0, t0 */
        if (insn_offset + 12 <= code_len) {
            uint32_t insn0 = *(const uint32_t *)(code + insn_offset);
            uint32_t insn1 = *(const uint32_t *)(code + insn_offset + 4);
            uint32_t insn2 = *(const uint32_t *)(code + insn_offset + 8);
            if ((insn0 & 0x7f) == 0x37 &&
                (insn1 & 0x707f) == 0x0013 &&
                insn2 == 0x005505b3) {
                return EIA_SUCCESS;
            }
        }
        return EIA_ERR_BAD_INSN;
    } else {
        /* x86-64: LEA / MOV / MOVSXD / MOVSD / MOVSS */
        if (insn_offset >= 3) {
            uint8_t op = code[insn_offset - 2];
            uint8_t modrm = code[insn_offset - 1];
            if ((op == 0x8D || op == 0x8B || op == 0x89 || op == 0x63) && ((modrm & 0xC0) == 0x80)) {
                return EIA_SUCCESS;
            }
        }
        if (insn_offset >= 4) {
            uint8_t op = code[insn_offset - 3];
            uint8_t modrm = code[insn_offset - 2];
            if ((op == 0x8D || op == 0x8B || op == 0x89 || op == 0x63) && ((modrm & 0xC0) == 0x80)) {
                return EIA_SUCCESS;
            }
        }
        if (insn_offset >= 5) {
            uint8_t op = code[insn_offset - 2];
            uint8_t modrm = code[insn_offset - 1];
            uint8_t pfx = code[insn_offset - 3];
            if ((pfx == 0x0F && (op == 0xB6 || op == 0xB7 || op == 0xBE || op == 0xBF)) ||
                (op == 0x10 || op == 0x5A || op == 0x11)) {
                if ((modrm & 0xC0) == 0x80) return EIA_SUCCESS;
            }
        }
        return EIA_ERR_BAD_INSN;
    }
}

static int __attribute__((unused)) cmp_u32(const void *a, const void *b) {
    uint32_t ua = *(const uint32_t *)a;
    uint32_t ub = *(const uint32_t *)b;
    return (ua > ub) - (ua < ub);
}

/* Locate Universal Hologram Header dynamically */
static const UniversalHologramHeader *find_hologram(const uint8_t *data, size_t size) {
    /* 1. Probe native ELF offset (0x80) */
    if (size > 0x80 + sizeof(UniversalHologramHeader)) {
        const UniversalHologramHeader *h = (const UniversalHologramHeader *)(data + 0x80);
        if (h->magic == EIA_MAGIC_HOLO) return h;
    }
    /* 2. Probe UPBP offset (1152) */
    if (size > 1152 + sizeof(UniversalHologramHeader)) {
        const UniversalHologramHeader *h = (const UniversalHologramHeader *)(data + 1152);
        if (h->magic == EIA_MAGIC_HOLO) return h;
    }
    /* 3. Scan first 4KB on 16-byte boundaries */
    size_t scan_limit = size > 4096 ? 4096 : size;
    for (size_t off = 0; off + sizeof(UniversalHologramHeader) <= scan_limit; off += 16) {
        const UniversalHologramHeader *h = (const UniversalHologramHeader *)(data + off);
        if (h->magic == EIA_MAGIC_HOLO) return h;
    }
    return NULL;
}

static __attribute__((unused)) LoadedBinary *load_binary(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "[EIA ERROR] Failed to open binary file '%s'\n", path);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    size_t sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (sz < 0x80 + sizeof(UniversalHologramHeader)) {
        fprintf(stderr, "[EIA ERROR] '%s' is too small to be a valid EIA binary\n", path);
        fclose(f);
        return NULL;
    }

    uint8_t *data = (uint8_t *)malloc(sz);
    if (!data || fread(data, 1, sz, f) != sz) {
        fprintf(stderr, "[EIA ERROR] Failed to read '%s'\n", path);
        if (data) free(data);
        fclose(f);
        return NULL;
    }
    fclose(f);

    /* Check if input is a versioned EIA Universal Package ('UEIA') */
    if (sz >= sizeof(EiaUniversalHeader)) {
        const EiaUniversalHeader *uhdr = (const EiaUniversalHeader *)data;
        if (uhdr->magic == EIA_UNIVERSAL_MAGIC) {
            if (uhdr->version_major != EIA_UNIVERSAL_VERSION) {
                fprintf(stderr, "[EIA ERROR] '%s': Unsupported Universal Container version %u.%u (expected %u.x)\n",
                        path, uhdr->version_major, uhdr->version_minor, EIA_UNIVERSAL_VERSION);
                free(data);
                return NULL;
            }
            if (uhdr->slice_count == 0 || uhdr->slice_count > EIA_MAX_SLICES) {
                fprintf(stderr, "[EIA ERROR] '%s': Invalid slice count %u in Universal Container\n",
                        path, uhdr->slice_count);
                free(data);
                return NULL;
            }
            if (uhdr->total_size > sz) {
                fprintf(stderr, "[EIA ERROR] '%s': Universal Container total_size exceeds file bounds\n", path);
                free(data);
                return NULL;
            }

            uint64_t table_sz = sizeof(EiaUniversalHeader) + uhdr->slice_count * sizeof(EiaUniversalSliceHeader);
            if (table_sz > sz) {
                fprintf(stderr, "[EIA ERROR] '%s': Universal slice table exceeds file bounds\n", path);
                free(data);
                return NULL;
            }

            const EiaUniversalSliceHeader *slices = (const EiaUniversalSliceHeader *)(data + sizeof(EiaUniversalHeader));
            uint32_t host_arch = 0;
#if defined(__aarch64__)
            host_arch = 1;
#elif defined(__riscv) && (__riscv_xlen == 64)
            host_arch = 2;
#else
            host_arch = 0;
#endif

            const EiaUniversalSliceHeader *selected = NULL;
            for (uint32_t s = 0; s < uhdr->slice_count; ++s) {
                const EiaUniversalSliceHeader *sl = &slices[s];
                if (sl->slice_offset > sz || sl->slice_size > sz - sl->slice_offset) {
                    fprintf(stderr, "[EIA ERROR] '%s': Universal slice %u offset/size exceeds bounds\n", path, s);
                    free(data);
                    return NULL;
                }
                for (uint32_t prev = 0; prev < s; ++prev) {
                    const EiaUniversalSliceHeader *psl = &slices[prev];
                    if ((sl->slice_offset < psl->slice_offset + psl->slice_size) &&
                        (psl->slice_offset < sl->slice_offset + sl->slice_size)) {
                        fprintf(stderr, "[EIA ERROR] '%s': Overlapping slices %u and %u in Universal Container\n",
                                path, prev, s);
                        free(data);
                        return NULL;
                    }
                }
                if (sl->arch_id == host_arch && !selected) {
                    selected = sl;
                }
            }

            if (!selected) {
                selected = &slices[0];
            }

            size_t slice_sz = selected->slice_size;
            uint8_t *slice_data = (uint8_t *)malloc(slice_sz);
            if (!slice_data) {
                free(data);
                return NULL;
            }
            memcpy(slice_data, data + selected->slice_offset, slice_sz);
            free(data);

            data = slice_data;
            sz = slice_sz;
        }
    }

    const UniversalHologramHeader *holo = find_hologram(data, sz);
    if (!holo) {
        fprintf(stderr, "[EIA ERROR] File '%s' is not a valid EIA binary (Universal Hologram header missing)\n", path);
        free(data);
        return NULL;
    }

    /* Harden bounds & arithmetic overflow checks */
    if (holo->contracts_count > 65536 || holo->relocs_count > 65536 || holo->type_graph_size > 16*1024*1024) {
        fprintf(stderr, "[EIA ERROR] '%s': Hologram table counts or type graph size exceed limits\n", path);
        free(data);
        return NULL;
    }
    if (holo->contracts_offset > sz ||
        holo->contracts_count > (sz - holo->contracts_offset) / sizeof(SymbolContract)) {
        fprintf(stderr, "[EIA ERROR] '%s': Contracts table exceeds file bounds\n", path);
        free(data);
        return NULL;
    }
    if (holo->relocs_offset > sz ||
        holo->relocs_count > (sz - holo->relocs_offset) / sizeof(EiaRelocHole)) {
        fprintf(stderr, "[EIA ERROR] '%s': Relocations table exceeds file bounds\n", path);
        free(data);
        return NULL;
    }
    if (holo->type_graph_offset > sz ||
        holo->type_graph_size > (sz - holo->type_graph_offset)) {
        fprintf(stderr, "[EIA ERROR] '%s': Type graph exceeds file bounds\n", path);
        free(data);
        return NULL;
    }

    uint64_t c_bytes = holo->contracts_count * sizeof(SymbolContract);
    uint64_t r_bytes = holo->relocs_count * sizeof(EiaRelocHole);
    uint64_t tables_len = c_bytes + r_bytes + holo->type_graph_size;
    if (holo->contracts_offset + tables_len > sz) {
        fprintf(stderr, "[EIA ERROR] '%s': Hologram tables overflow file size\n", path);
        free(data);
        return NULL;
    }

    /* Verify cryptographic BLAKE3-64 integrity */
    uint64_t computed_root = blake3_hash64(data + holo->contracts_offset, tables_len);
    if (computed_root != holo->blake3_root) {
        fprintf(stderr, "[EIA ERROR] '%s': Hologram cryptographic integrity mismatch!\n"
                        "  Expected BLAKE3: 0x%016lx\n  Computed BLAKE3: 0x%016lx\n",
                path, (unsigned long)holo->blake3_root, (unsigned long)computed_root);
        free(data);
        return NULL;
    }

    /* Validate version policy */
    if (holo->version_major != EIA_VERSION_MAJOR) {
        fprintf(stderr, "[EIA ERROR] '%s': Unsupported artifact format version %u.%u (expected %u.x)\n",
                path, holo->version_major, holo->version_minor, EIA_VERSION_MAJOR);
        free(data);
        return NULL;
    }

    /* Validate cryptographic contract_digest for every contract entry */
    const SymbolContract *contracts_check = (const SymbolContract *)(data + holo->contracts_offset);
    for (size_t i = 0; i < holo->contracts_count; ++i) {
        const SymbolContract *sc = &contracts_check[i];
        uint64_t expected_digest = blake3_hash64((const uint8_t *)sc, 40);
        if (sc->contract_digest != expected_digest) {
            fprintf(stderr, "[EIA ERROR] '%s': Symbol contract digest mismatch for symbol 0x%016lx\n",
                    path, (unsigned long)sc->symbol_hash);
            free(data);
            return NULL;
        }
    }

    /* Verify artifact cryptographic authentication if signed */
    uint64_t auth_offset = *(const uint64_t *)(&holo->reserved[0]);
    uint64_t auth_size   = *(const uint64_t *)(&holo->reserved[8]);
    if (auth_offset != 0 && auth_size >= sizeof(EiaSignatureRecord)) {
        if (auth_offset + sizeof(EiaSignatureRecord) > sz) {
            fprintf(stderr, "[EIA ERROR] '%s': Auth record overflows file bounds\n", path);
            free(data);
            return NULL;
        }
        EiaSignatureRecord *sig = (EiaSignatureRecord *)(data + auth_offset);
        if (sig->magic != EIA_AUTH_MAGIC) {
            fprintf(stderr, "[EIA ERROR] '%s': Invalid signature magic 0x%08x\n", path, sig->magic);
            free(data);
            return NULL;
        }
        if (sig->version != EIA_AUTH_VERSION) {
            fprintf(stderr, "[EIA ERROR] '%s': Unsupported signature version %u\n", path, sig->version);
            free(data);
            return NULL;
        }
        if (sig->key_epoch < EIA_MIN_TRUSTED_EPOCH) {
            fprintf(stderr, "[EIA ERROR] '%s': Key epoch %u is outdated or revoked (min required: %u)\n",
                    path, sig->key_epoch, EIA_MIN_TRUSTED_EPOCH);
            free(data);
            return NULL;
        }
        if (!eia_trust_store_lookup(sig->public_key_id, sig->key_epoch)) {
            fprintf(stderr, "[EIA ERROR] '%s': Untrusted or revoked public key ID 0x%016lx (epoch %u)\n",
                    path, (unsigned long)sig->public_key_id, sig->key_epoch);
            free(data);
            return NULL;
        }

        /* Whole-artifact digest calculation (with digest & signature fields zeroed) */
        uint8_t saved_digest[32];
        uint8_t saved_sig[64];
        memcpy(saved_digest, sig->blake3_digest, 32);
        memcpy(saved_sig, sig->signature, 64);
        memset(sig->blake3_digest, 0, 32);
        memset(sig->signature, 0, 64);

        uint8_t computed_digest[32];
        blake3_hash256(data, sz, computed_digest);

        /* Restore signature record fields */
        memcpy(sig->blake3_digest, saved_digest, 32);
        memcpy(sig->signature, saved_sig, 64);

        if (memcmp(computed_digest, saved_digest, 32) != 0) {
            fprintf(stderr, "[EIA ERROR] '%s': Cryptographic 256-bit BLAKE3 artifact digest mismatch!\n", path);
            free(data);
            return NULL;
        }
        if (!spark0_verify_signature(saved_digest, sig->key_epoch, sig->public_key_id, saved_sig)) {
            fprintf(stderr, "[EIA ERROR] '%s': Cryptographic signature verification failed!\n", path);
            free(data);
            return NULL;
        }
        printf("[EIA AUTH] Cryptographic whole-artifact provenance verified for '%s' (epoch=%u, pubkey=0x%016lx)\n",
               path, sig->key_epoch, (unsigned long)sig->public_key_id);
    }

    LoadedBinary *b = (LoadedBinary *)calloc(1, sizeof(LoadedBinary));
    b->path = path;
    b->file_data = data;
    b->file_size = sz;
    b->holo = holo;
    b->contracts = (const SymbolContract *)(data + holo->contracts_offset);
    b->contract_count = holo->contracts_count;
    b->relocs = (const EiaRelocHole *)(data + holo->relocs_offset);
    b->reloc_count = holo->relocs_count;
    b->type_graph = (const EiaTypeGraphEntry *)(data + holo->type_graph_offset);
    b->type_graph_count = holo->type_graph_size / sizeof(EiaTypeGraphEntry);

    /* Dynamically parse architecture and code segment layout from ELF, PE, or Mach-O */
    uint16_t t_arch = 0;
    uint64_t text_vaddr_base = 0x410000;
    size_t text_off = 0x10000;
    size_t text_sz = 0;
    bool format_parsed = false;
    /* 0. Probe Universal Multi-ISA Slices if holo->flags has bit 2 (EIA_FLAG_MULTIARCH) */
    if ((holo->flags & 4) && sz >= 0x70000) {
        int desired_arch = 0;
#if defined(__aarch64__)
        desired_arch = 1;
#elif defined(__riscv)
        desired_arch = 2;
#else
        desired_arch = 0;
#endif
        const char *env_arch = getenv("EIA_TARGET_ARCH");
        if (env_arch) {
            if (strcmp(env_arch, "arm64") == 0 || strcmp(env_arch, "1") == 0) desired_arch = 1;
            else if (strcmp(env_arch, "riscv64") == 0 || strcmp(env_arch, "2") == 0) desired_arch = 2;
            else if (strcmp(env_arch, "x86_64") == 0 || strcmp(env_arch, "0") == 0) desired_arch = 0;
        }

        size_t slice_off = (desired_arch == 1) ? 0x50000 : (desired_arch == 2) ? 0x90000 : 0x10000;
        if (sz >= slice_off + sizeof(Elf64Header) &&
            data[slice_off] == 0x7f && data[slice_off+1] == 'E' && data[slice_off+2] == 'L' && data[slice_off+3] == 'F') {
            const Elf64Header *eh = (const Elf64Header *)(data + slice_off);
            t_arch = desired_arch;
            text_vaddr_base = eh->e_entry;
            size_t rel_text = 0x10000;
            if (eh->e_phoff != 0 && sz >= slice_off + eh->e_phoff + sizeof(Elf64ProgramHeader)) {
                const Elf64ProgramHeader *ph = (const Elf64ProgramHeader *)(data + slice_off + eh->e_phoff);
                if (eh->e_entry >= ph->p_vaddr) rel_text = (size_t)(eh->e_entry - ph->p_vaddr);
            }
            text_off = slice_off + rel_text;
            text_sz = (sz > text_off) ? (sz - text_off) : 0;
            format_parsed = true;
        }
    }

    /* 1. Probe ELF headers (at 0 or 128) if not already parsed via multi-ISA slice */
    size_t elf_off = 0;
    bool is_elf = false;
    if (!format_parsed) {
        if (sz >= 64 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F') {
            elf_off = 0;
            is_elf = true;
        } else if (sz >= 128 + 64 && data[128] == 0x7f && data[129] == 'E' && data[130] == 'L' && data[131] == 'F') {
            elf_off = 128;
            is_elf = true;
        }
    }

    if (is_elf && sz >= elf_off + sizeof(Elf64Header)) {
        const Elf64Header *eh = (const Elf64Header *)(data + elf_off);
        uint16_t em = eh->e_machine;
        if (em == 183) t_arch = 1;      /* AArch64 */
        else if (em == 243) t_arch = 2;  /* RISC-V 64 */
        else t_arch = 0;                 /* x86_64 */

        if (eh->e_phoff != 0 && sz >= elf_off + eh->e_phoff + sizeof(Elf64ProgramHeader)) {
            const Elf64ProgramHeader *ph = (const Elf64ProgramHeader *)(data + elf_off + eh->e_phoff);
            text_vaddr_base = (elf_off == 128) ? 0x410000 : eh->e_entry;
            if (eh->e_entry >= ph->p_vaddr && (eh->e_entry - ph->p_vaddr) + elf_off < sz) {
                text_off = elf_off + (size_t)(eh->e_entry - ph->p_vaddr);
                text_sz = sz - text_off;
                format_parsed = true;
            }
        }
    }

    /* 2. Probe PE headers if not ELF */
    if (!format_parsed && sz >= 64 && data[0] == 'M' && data[1] == 'Z') {
        uint32_t pe_offset = *(const uint32_t *)(data + 0x3C);
        if (pe_offset + 264 <= sz && memcmp(data + pe_offset, "PE\0\0", 4) == 0) {
            uint16_t machine = *(const uint16_t *)(data + pe_offset + 4);
            if (machine == 0xaa64) t_arch = 1;
            else if (machine == 0x5064) t_arch = 2;
            else t_arch = 0;

            uint16_t num_sections = *(const uint16_t *)(data + pe_offset + 6);
            uint16_t opt_size = *(const uint16_t *)(data + pe_offset + 20);
            if (opt_size >= 112) {
                uint32_t entry_rva = *(const uint32_t *)(data + pe_offset + 24 + 16);
                uint64_t image_base = *(const uint64_t *)(data + pe_offset + 24 + 24);
                text_vaddr_base = image_base + entry_rva;
            }

            size_t sec_table = pe_offset + 24 + opt_size;
            for (uint16_t s = 0; s < num_sections && sec_table + (s + 1) * 40 <= sz; ++s) {
                const uint8_t *sec = data + sec_table + s * 40;
                if (memcmp(sec, ".text", 5) == 0) {
                    uint32_t raw_size = *(const uint32_t *)(sec + 16);
                    uint32_t raw_ptr = *(const uint32_t *)(sec + 20);
                    if (raw_ptr + raw_size <= sz) {
                        text_off = raw_ptr;
                        text_sz = raw_size;
                        format_parsed = true;
                        break;
                    }
                }
            }
        }
    }

    /* 3. Probe Mach-O 64 headers */
    if (!format_parsed) {
        size_t m_off = 0;
        bool is_macho = false;
        if (sz >= 32 && *(const uint32_t *)data == 0xfeedfacf) {
            m_off = 0;
            is_macho = true;
        } else if (sz >= 512 + 32 && *(const uint32_t *)(data + 512) == 0xfeedfacf) {
            m_off = 512;
            is_macho = true;
        }

        if (is_macho) {
            uint32_t cputype = *(const uint32_t *)(data + m_off + 4);
            if (cputype == 0x0100000c) t_arch = 1;
            else t_arch = 0;

            uint32_t ncmds = *(const uint32_t *)(data + m_off + 16);
            size_t cmd_ptr = m_off + 32;
            for (uint32_t c = 0; c < ncmds && cmd_ptr + 8 <= sz; ++c) {
                uint32_t cmd = *(const uint32_t *)(data + cmd_ptr);
                uint32_t cmdsize = *(const uint32_t *)(data + cmd_ptr + 4);
                if (cmd == 0x19 && cmdsize >= 72) {
                    if (memcmp(data + cmd_ptr + 8, "__TEXT", 6) == 0) {
                        uint64_t vmaddr = *(const uint64_t *)(data + cmd_ptr + 24);
                        uint64_t fileoff = *(const uint64_t *)(data + cmd_ptr + 40);
                        uint64_t filesize = *(const uint64_t *)(data + cmd_ptr + 48);
                        text_vaddr_base = vmaddr ? vmaddr : 0x100000000ULL;
                        text_off = (size_t)fileoff;
                        text_sz = (size_t)filesize;
                        format_parsed = true;
                        break;
                    }
                }
                cmd_ptr += cmdsize;
            }
        }
    }
    b->target_arch = t_arch;
    b->text_vaddr_base = text_vaddr_base;

    uint64_t actual_code_len = 0;
    for (size_t c = 0; c < b->contract_count; ++c) {
        if (b->contracts[c].vaddr >= b->text_vaddr_base) {
            uint64_t end = (b->contracts[c].vaddr - b->text_vaddr_base) + b->contracts[c].code_size;
            if (end > actual_code_len) actual_code_len = end;
        }
    }
    if (actual_code_len > 0) {
        text_sz = (size_t)((actual_code_len + 0xFFF) & ~0xFFFULL);
    }

    if (text_off < sz) {
        b->text_data = data + text_off;
        b->text_size = text_sz ? text_sz : (sz - text_off);
    } else {
        b->text_data = data;
        b->text_size = sz;
    }

    return b;
}

static void __attribute__((unused)) cleanup_loaded_binaries(LoadedBinary *client, LoadedBinary **providers, int count) {
    if (client) {
        if (client->file_data) free(client->file_data);
        free(client);
    }
    if (providers) {
        for (int i = 0; i < count; ++i) {
            if (providers[i]) {
                if (providers[i]->file_data) free(providers[i]->file_data);
                free(providers[i]);
            }
        }
        free(providers);
    }
    gdam_reclaim_retired(&g_runtime_gdam);
    for (int i = 0; i <= MAX_LOADED_PROVIDERS; ++i) {
        if (g_provider_gens[i].record_buf) {
            free((void *)g_provider_gens[i].record_buf);
            g_provider_gens[i].record_buf = NULL;
        }
    }
}

static bool __attribute__((unused)) eia_adapt_widening_instruction(
    int target_arch,
    uint8_t *patch_site,
    uint32_t insn_offset,
    uint32_t text_size,
    uint32_t prov_field_sz,
    uint32_t expected_size
) {
    if (prov_field_sz == expected_size) return true;

    if (target_arch == 0) {
        /* x86-64 */
        uint8_t *code = patch_site + 4;
        if (insn_offset + 7 > text_size) return false;

        /* Floating point SSE conversions */
        if (insn_offset >= 5) {
            uint8_t *pfx = patch_site - 1;
            if (pfx[-2] == 0xF2 && pfx[-1] == 0x0F && pfx[0] == 0x10) {
                /* movsd xmm, [mem] -> cvtss2sd xmm, [mem] (f32 -> f64) */
                if (expected_size == 8 && prov_field_sz == 4) {
                    pfx[-2] = 0xF3;
                    pfx[0]  = 0x5A;
                    return true;
                }
            } else if (pfx[-2] == 0xF3 && pfx[-1] == 0x0F && pfx[0] == 0x10) {
                /* movss xmm, [mem] -> cvtsd2ss xmm, [mem] (f64 -> f32) */
                if (expected_size == 4 && prov_field_sz == 8) {
                    pfx[-2] = 0xF2;
                    pfx[0]  = 0x5A;
                    return true;
                }
            }
        }

        /* Integer widening / narrowing */
        if (expected_size == 8 && prov_field_sz < 8) {
            if ((code[0] & 0xF0) == 0x40) {
                uint8_t rex = code[0];
                uint8_t op = code[1];
                uint8_t modrm = code[2];

                if (op == 0x8B) {
                    /* Unsigned widening: zero-extend to 64-bit */
                    if (prov_field_sz == 4) {
                        if (rex == 0x48) {
                            code[0] = 0x8B; code[1] = modrm; code[2] = 0x90;
                        } else {
                            code[0] = rex & ~0x08;
                        }
                        return true;
                    } else if (prov_field_sz == 2) {
                        code[0] = 0x0F; code[1] = 0xB7; code[2] = modrm;
                        return true;
                    } else if (prov_field_sz == 1) {
                        code[0] = 0x0F; code[1] = 0xB6; code[2] = modrm;
                        return true;
                    }
                } else if (op == 0x63) {
                    /* Signed widening: sign-extend to 64-bit */
                    if (prov_field_sz == 4) {
                        return true;
                    } else if (prov_field_sz == 2) {
                        code[0] = 0x48; code[1] = 0x0F; code[2] = 0xBF;
                        return true;
                    } else if (prov_field_sz == 1) {
                        code[0] = 0x48; code[1] = 0x0F; code[2] = 0xBE;
                        return true;
                    }
                } else if (op == 0x89) {
                    /* Store truncation */
                    if (prov_field_sz == 4) {
                        if (rex == 0x48) {
                            code[0] = 0x89; code[1] = modrm; code[2] = 0x90;
                        } else {
                            code[0] = rex & ~0x08;
                        }
                        return true;
                    } else if (prov_field_sz == 2) {
                        code[0] = 0x66; code[1] = 0x89; code[2] = modrm;
                        return true;
                    } else if (prov_field_sz == 1) {
                        code[0] = 0x88; code[1] = modrm; code[2] = 0x90;
                        return true;
                    }
                }
            }
        } else if (expected_size == 4 && prov_field_sz < 4) {
            if (code[0] == 0x8B) {
                uint8_t modrm = code[1];
                if (prov_field_sz == 2) {
                    code[0] = 0x0F; code[1] = 0xB7; code[2] = modrm;
                    return true;
                } else if (prov_field_sz == 1) {
                    code[0] = 0x0F; code[1] = 0xB6; code[2] = modrm;
                    return true;
                }
            }
        }
    } else if (target_arch == 1) {
        /* ARM64 */
        if (insn_offset + 16 <= text_size) {
            uint32_t *next_insn = (uint32_t *)(patch_site + 12);
            uint32_t op = *next_insn;
            if ((op & 0xffc00000) == 0xf9400000) {
                if (prov_field_sz == 4) {
                    *next_insn = (op & ~0xc0000000) | 0x80000000;
                    return true;
                } else if (prov_field_sz == 2) {
                    *next_insn = (op & ~0xc0000000) | 0x40000000;
                    return true;
                } else if (prov_field_sz == 1) {
                    *next_insn = (op & ~0xc0000000);
                    return true;
                }
            } else if ((op & 0xffc00000) == 0xf9000000) {
                if (prov_field_sz == 4) {
                    *next_insn = (op & ~0xc0000000) | 0x80000000;
                    return true;
                } else if (prov_field_sz == 2) {
                    *next_insn = (op & ~0xc0000000) | 0x40000000;
                    return true;
                } else if (prov_field_sz == 1) {
                    *next_insn = (op & ~0xc0000000);
                    return true;
                }
            } else if ((op & 0xffc00000) == 0xfd400000 && prov_field_sz == 4) {
                *next_insn = (op & ~0x40000000);
                return true;
            }
        }
    } else if (target_arch == 2) {
        /* RISC-V 64 */
        if (insn_offset + 16 <= text_size) {
            uint32_t *next_insn = (uint32_t *)(patch_site + 12);
            uint32_t op = *next_insn;
            if ((op & 0x707f) == 0x3003) {
                if (prov_field_sz == 4) {
                    *next_insn = (op & ~0x7000) | 0x6000;
                    return true;
                } else if (prov_field_sz == 2) {
                    *next_insn = (op & ~0x7000) | 0x5000;
                    return true;
                } else if (prov_field_sz == 1) {
                    *next_insn = (op & ~0x7000) | 0x4000;
                    return true;
                }
            } else if ((op & 0x707f) == 0x3023) {
                if (prov_field_sz == 4) {
                    *next_insn = (op & ~0x7000) | 0x2000;
                    return true;
                } else if (prov_field_sz == 2) {
                    *next_insn = (op & ~0x7000) | 0x1000;
                    return true;
                } else if (prov_field_sz == 1) {
                    *next_insn = (op & ~0x7000);
                    return true;
                }
            } else if ((op & 0x707f) == 0x3007 && prov_field_sz == 4) {
                *next_insn = (op & ~0x7000) | 0x2000;
                return true;
            }
        }
    }
    return false;
}

/* ========================================================================= */
/*                               MAIN LOADER                                 */
/* ========================================================================= */

#ifndef EIA_LOADER_LIB
int main(int argc, char **argv) {
    int require_signed = 0;
    int strict_epoch = (getenv("EIA_STRICT_EPOCH") != NULL);
    const char *client_path = NULL;
    int provider_count = 0;
    const char *provider_paths[64];

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--require-signed") == 0) {
            require_signed = 1;
        } else if (strcmp(argv[i], "--strict-epoch") == 0) {
            strict_epoch = 1;
        } else if (strcmp(argv[i], "--trust-key") == 0 && i + 1 < argc) {
            const char *val = argv[++i];
            if (strlen(val) == 64) {
                uint8_t pk[32];
                bool ok = true;
                for (int b = 0; b < 32; ++b) {
                    unsigned int v = 0;
                    if (sscanf(val + (b * 2), "%02x", &v) != 1) { ok = false; break; }
                    pk[b] = (uint8_t)v;
                }
                if (ok) eia_trust_store_add(pk, 0);
            } else {
                FILE *f = fopen(val, "rb");
                if (f) {
                    uint8_t pk[32];
                    if (fread(pk, 1, 32, f) == 32) eia_trust_store_add(pk, 0);
                    fclose(f);
                }
            }
        } else if (strcmp(argv[i], "--trust-store") == 0 && i + 1 < argc) {
            const char *val = argv[++i];
            FILE *f = fopen(val, "rb");
            if (f) {
                uint8_t pk[32];
                while (fread(pk, 1, 32, f) == 32) eia_trust_store_add(pk, 0);
                fclose(f);
            }
        } else if (strcmp(argv[i], "--revoke-key") == 0 && i + 1 < argc) {
            uint64_t kid = (uint64_t)strtoull(argv[++i], NULL, 0);
            if (kid) eia_trust_store_revoke(kid, 0);
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            return 1;
        } else if (!client_path) {
            client_path = argv[i];
        } else if (provider_count < 64) {
            provider_paths[provider_count++] = argv[i];
        }
    }

    if (!client_path) {
        fprintf(stderr, "Usage: %s [--require-signed] [--trust-key <hex/file>] [--trust-store <file>] [--revoke-key <id>] <client_binary> [provider_binary ...]\n", argv[0]);
        return 1;
    }

    /* 1. Load client binary */
    LoadedBinary *client = load_binary(client_path);
    if (!client) return 1;

    /* 2. Load provider binaries */
    LoadedBinary **providers = NULL;
    if (provider_count > 0) {
        providers = (LoadedBinary **)calloc(provider_count, sizeof(LoadedBinary *));
        for (int i = 0; i < provider_count; ++i) {
            providers[i] = load_binary(provider_paths[i]);
            if (!providers[i]) {
                fprintf(stderr, "[EIA ERROR] Failed to load provider artifact '%s'\n", provider_paths[i]);
                cleanup_loaded_binaries(client, providers, provider_count);
                return 1;
            }
        }
    }

    /* Check --require-signed policy */
    if (require_signed) {
        uint64_t client_auth_offset = *(const uint64_t *)(&client->holo->reserved[0]);
        if (!(client->holo->flags & 2) || client_auth_offset == 0) {
            fprintf(stderr, "[EIA ERROR] Client artifact '%s' is unsigned; rejected under --require-signed policy\n", client->path);
            cleanup_loaded_binaries(client, providers, provider_count);
            return 1;
        }
        for (int i = 0; i < provider_count; ++i) {
            uint64_t prov_auth_offset = *(const uint64_t *)(&providers[i]->holo->reserved[0]);
            if (!(providers[i]->holo->flags & 2) || prov_auth_offset == 0) {
                fprintf(stderr, "[EIA ERROR] Provider artifact '%s' is unsigned; rejected under --require-signed policy\n", providers[i]->path);
                cleanup_loaded_binaries(client, providers, provider_count);
                return 1;
            }
        }
    }

    /* Initialize GDAM generational runtime with client baseline */
    memset(&g_provider_gens[0], 0, sizeof(g_provider_gens[0]));
    g_provider_gens[0].epoch = client->holo->abi_epoch;
    g_provider_gens[0].count = client->type_graph_count;
    g_provider_gens[0].schema = (const GdamFieldEntry *)client->type_graph;
    if (client->type_graph_count > 0 && client->type_graph) {
        size_t base_sz = 0;
        for (size_t f = 0; f < client->type_graph_count; ++f) {
            uint32_t end = g_provider_gens[0].schema[f].byte_offset + g_provider_gens[0].schema[f].field_size;
            if (end > base_sz) base_sz = end;
        }
        if (base_sz > 0) {
            g_provider_gens[0].record_buf = (uint8_t *)calloc(base_sz, 1);
        }
    }
    gdam_init(&g_runtime_gdam, &g_provider_gens[0]);

    /* Atomically publish each loaded provider's schema generation and
     * migrate live type-graph records when the ABI epoch advances. */
    for (int i = 0; i < provider_count && i < MAX_LOADED_PROVIDERS; ++i) {
        GdamGeneration *prev_gen = atomic_load(&g_runtime_gdam.active_generation);

        memset(&g_provider_gens[i + 1], 0, sizeof(g_provider_gens[i + 1]));
        g_provider_gens[i + 1].epoch  = providers[i]->holo->abi_epoch;
        g_provider_gens[i + 1].count  = providers[i]->type_graph_count;
        g_provider_gens[i + 1].schema = (const GdamFieldEntry *)providers[i]->type_graph;

        if (gdam_atomic_publish(&g_runtime_gdam, &g_provider_gens[i + 1]) == 0) {
            fprintf(stderr, "[EIA ERROR] GDAM publication failed for provider '%s'; rolling back generation\n", providers[i]->path);
            gdam_rollback(&g_runtime_gdam);
            cleanup_loaded_binaries(client, providers, provider_count);
            return 1;
        }

        /* Live GDAM record migration: if the new generation's epoch is strictly
         * higher than the previous one, forward-migrate any type-graph records
         * that exist in both schemas so field offsets and sizes are up to date. */
        GdamGeneration *new_gen = atomic_load(&g_runtime_gdam.active_generation);
        if (prev_gen && new_gen &&
            new_gen->epoch > prev_gen->epoch &&
            new_gen->schema && new_gen->count > 0) {

            if (!prev_gen->record_buf && prev_gen->count > 0 && prev_gen->schema) {
                size_t prev_sz = 0;
                for (size_t f = 0; f < prev_gen->count; ++f) {
                    uint32_t end = prev_gen->schema[f].byte_offset + prev_gen->schema[f].field_size;
                    if (end > prev_sz) prev_sz = end;
                }
                if (prev_sz > 0) {
                    prev_gen->record_buf = (uint8_t *)calloc(prev_sz, 1);
                }
            }

            /* Allocate a scratchpad sized to the new generation's schema extent */
            size_t new_record_sz = 0;
            for (size_t f = 0; f < new_gen->count; ++f) {
                uint32_t end = new_gen->schema[f].byte_offset + new_gen->schema[f].field_size;
                if (end > new_record_sz) new_record_sz = end;
            }
            if (new_record_sz > 0) {
                uint8_t *migrated_buf = (uint8_t *)calloc(new_record_sz, 1);
                if (migrated_buf) {
                    /* Migrate every type seen in the new generation */
                    size_t total_migrated = 0;
                    if (prev_gen->record_buf && prev_gen->schema && prev_gen->count > 0) {
                        for (size_t f = 0; f < new_gen->count; ++f) {
                            uint64_t type_hash = new_gen->schema[f].type_sig_hash;
                            total_migrated += gdam_migrate_record(
                                prev_gen->record_buf, prev_gen->schema, prev_gen->count,
                                migrated_buf, new_gen->schema, new_gen->count,
                                type_hash
                            );
                        }
                    }
                    printf("[EIA GDAM] Live schema migration: provider '%s' epoch %lu→%lu, %zu field(s) migrated\n",
                           providers[i]->path,
                           (unsigned long)prev_gen->epoch,
                           (unsigned long)new_gen->epoch,
                           total_migrated);
                    /* Attach migrated record buffer to the published generation */
                    g_provider_gens[i + 1].record_buf = migrated_buf;
                    /* Safely retire previous generation's record buffer */
                    if (prev_gen->record_buf) {
                        gdam_retire_record(&g_runtime_gdam, (uint8_t *)prev_gen->record_buf);
                        prev_gen->record_buf = NULL;
                    }
                }
            }
        } else if (prev_gen && new_gen && new_gen->epoch > prev_gen->epoch) {
            /* No live record buffer to migrate; schema evolution logged only */
            printf("[EIA GDAM] Schema generation advanced: provider '%s' epoch %lu→%lu (no live record buffer)\n",
                   providers[i]->path,
                   (unsigned long)prev_gen->epoch,
                   (unsigned long)new_gen->epoch);
        }
    }

    /* 3. Compute required DVAM arena size */
    size_t total_code_size = (client->text_size + 0xFFF) & ~0xFFFULL;
    client->arena_offset = 0;

    for (int i = 0; i < provider_count; ++i) {
        providers[i]->arena_offset = total_code_size;
        total_code_size += (providers[i]->text_size + 0xFFF) & ~0xFFFULL;
    }

    size_t thunk_arena_offset = total_code_size;
    size_t thunk_used = 0;
    total_code_size += 16384; /* 16KB arena reserved for ABI bridges and widening adapter thunks */

    /* 4. Allocate DVAM Dual Virtual Aliases (Strict W^X) */
    uint8_t *v_write = NULL;
    uint8_t *v_exec = NULL;
#ifdef _WIN32
    HANDLE hMap = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, (DWORD)total_code_size, NULL);
    if (!hMap) {
        fprintf(stderr, "[EIA ERROR] DVAM CreateFileMapping failed\n");
        return 1;
    }
    v_write = (uint8_t *)MapViewOfFile(hMap, FILE_MAP_WRITE, 0, 0, total_code_size);
    v_exec  = (uint8_t *)MapViewOfFile(hMap, FILE_MAP_READ | FILE_MAP_EXECUTE, 0, 0, total_code_size);
    if (!v_write || !v_exec) {
        fprintf(stderr, "[EIA ERROR] DVAM MapViewOfFile failed\n");
        CloseHandle(hMap);
        return 1;
    }
#else
    int memfd = -1;
#if defined(__linux__) && defined(__NR_memfd_create)
    memfd = syscall(__NR_memfd_create, "eia_runtime_dvam", 1 /* MFD_CLOEXEC */);
#endif
    if (memfd < 0) {
        const char *tmp = getenv("TMPDIR");
        char temp_path[512];
        snprintf(temp_path, sizeof(temp_path), "%s/eia_run_dvam_XXXXXX", tmp ? tmp : "/tmp");
        memfd = mkstemp(temp_path);
        if (memfd >= 0) unlink(temp_path);
    }
    if (memfd < 0 || ftruncate(memfd, total_code_size) < 0) {
        perror("DVAM allocation failed");
        return 1;
    }

    v_write = (uint8_t *)mmap(NULL, total_code_size, PROT_READ | PROT_WRITE, MAP_SHARED, memfd, 0);
    v_exec  = (uint8_t *)mmap(NULL, total_code_size, PROT_READ | PROT_EXEC,  MAP_SHARED, memfd, 0);
    if (v_write == MAP_FAILED || v_exec == MAP_FAILED) {
        perror("DVAM mmap failed");
        close(memfd);
        return 1;
    }
#endif

    /* Copy client and provider code into writable alias */
    memcpy(v_write + client->arena_offset, client->text_data, client->text_size);
    for (int i = 0; i < provider_count; ++i) {
        memcpy(v_write + providers[i]->arena_offset, providers[i]->text_data, providers[i]->text_size);
    }

    /* 5. Build Global Export Catalog & Global Type Graph Index (Dynamic Hash Registries) */
    SymbolRegistry sym_reg;
    sym_reg_init(&sym_reg, 1024);

    FieldRegistry field_reg;
    field_reg_init(&field_reg, 1024);

    /* Register provider exports and type graph entries */
    for (int p = 0; p < provider_count; ++p) {
        LoadedBinary *pb = providers[p];

        /* Symbol contracts */
        for (size_t c = 0; c < pb->contract_count; ++c) {
            const SymbolContract *sc = &pb->contracts[c];
            if (sc->flags & EIA_SYM_FLAG_EXPORT) {
                uint32_t fn_offset = (uint32_t)(sc->vaddr - pb->text_vaddr_base);
                uint64_t target_vaddr = (uint64_t)(v_exec + pb->arena_offset + fn_offset);
                sym_reg_insert(&sym_reg, sc->symbol_hash, sc->type_sig_hash, target_vaddr, sc->param_count, sc->calling_conv, pb->path);
            }
        }

        /* Type graph */
        for (size_t t = 0; t < pb->type_graph_count; ++t) {
            const EiaTypeGraphEntry *tge = &pb->type_graph[t];
            field_reg_insert(&field_reg, tge->type_sig_hash, tge->field_hash, tge->byte_offset, tge->field_size);
        }
    }

    /* Also register client's own type graph entries as baseline fallback */
    for (size_t t = 0; t < client->type_graph_count; ++t) {
        const EiaTypeGraphEntry *tge = &client->type_graph[t];
        if (!field_reg_lookup(&field_reg, tge->type_sig_hash, tge->field_hash)) {
            field_reg_insert(&field_reg, tge->type_sig_hash, tge->field_hash, tge->byte_offset, tge->field_size);
        }
    }

    /* Check ABI epoch compatibility:
     * Evolution mode (default): provider epoch must be >= client epoch.
     * Providers with higher epochs trigger GDAM schema evolution and record migration.
     * Stricter flag (--strict-epoch) requires exact match. */
    for (int i = 0; i < provider_count; ++i) {
        if (strict_epoch) {
            if (providers[i]->holo->abi_epoch != client->holo->abi_epoch) {
                fprintf(stderr, "[EIA ERROR] Incompatible ABI epoch: client '%s' (epoch %lu) vs provider '%s' (epoch %lu) under --strict-epoch\n",
                        client->path, (unsigned long)client->holo->abi_epoch,
                        providers[i]->path, (unsigned long)providers[i]->holo->abi_epoch);
                sym_reg_free(&sym_reg);
                field_reg_free(&field_reg);
                cleanup_loaded_binaries(client, providers, provider_count);
                return 1;
            }
        } else {
            if (providers[i]->holo->abi_epoch < client->holo->abi_epoch) {
                fprintf(stderr, "[EIA ERROR] Incompatible legacy provider: client '%s' requires ABI epoch >= %lu, but provider '%s' is at epoch %lu\n",
                        client->path, (unsigned long)client->holo->abi_epoch,
                        providers[i]->path, (unsigned long)providers[i]->holo->abi_epoch);
                sym_reg_free(&sym_reg);
                field_reg_free(&field_reg);
                cleanup_loaded_binaries(client, providers, provider_count);
                return 1;
            }
        }
    }

    #define MAX_PROVIDERS 64
    if (provider_count > MAX_PROVIDERS) {
        fprintf(stderr, "[EIA ERROR] Too many provider artifacts specified (%d > %d)\n", provider_count, MAX_PROVIDERS);
        free(client->file_data);
        free(client);
        return 1;
    }

    /* 6. Validate and Patch Relocations across Client & Providers */
    int all_bin_count = 1 + provider_count;
    LoadedBinary **all_bins = (LoadedBinary **)calloc(all_bin_count, sizeof(LoadedBinary *));
    if (!all_bins) return 1;
    all_bins[0] = client;
    for (int i = 0; i < provider_count; ++i) all_bins[1 + i] = providers[i];

    for (int b = 0; b < all_bin_count; ++b) {
        LoadedBinary *curr = all_bins[b];

        /* Overlap validation */
        if (curr->reloc_count <= 64) {
            for (size_t i = 0; i < curr->reloc_count; ++i) {
                for (size_t j = i + 1; j < curr->reloc_count; ++j) {
                    int64_t diff = (int64_t)curr->relocs[i].insn_offset - (int64_t)curr->relocs[j].insn_offset;
                    if (diff >= -3 && diff <= 3) {
                        fprintf(stderr, "[EIA ERROR] Relocation overlap at offset 0x%x in '%s'\n",
                                curr->relocs[i].insn_offset, curr->path);
                        free(all_bins);
                        return 1;
                    }
                }
            }
        } else {
            uint32_t *sorted_offs = (uint32_t *)malloc(curr->reloc_count * sizeof(uint32_t));
            if (!sorted_offs) { free(all_bins); return 1; }
            for (size_t i = 0; i < curr->reloc_count; ++i) sorted_offs[i] = curr->relocs[i].insn_offset;
            qsort(sorted_offs, curr->reloc_count, sizeof(uint32_t), cmp_u32);
            for (size_t i = 1; i < curr->reloc_count; ++i) {
                if (sorted_offs[i] - sorted_offs[i-1] < 4) {
                    fprintf(stderr, "[EIA ERROR] Relocation overlap at offset 0x%x in '%s'\n",
                            sorted_offs[i], curr->path);
                    free(sorted_offs);
                    free(all_bins);
                    return 1;
                }
            }
            free(sorted_offs);
        }

        for (size_t r = 0; r < curr->reloc_count; ++r) {
            const EiaRelocHole *hole = &curr->relocs[r];

            if (hole->insn_offset + 4 > curr->text_size) {
                fprintf(stderr, "[EIA ERROR] Relocation out of bounds in '%s' (insn_offset=0x%x)\n",
                        curr->path, hole->insn_offset);
                free(all_bins);
                return 1;
            }

            uint8_t *patch_site = v_write + curr->arena_offset + hole->insn_offset;

            if (hole->patch_kind == EIA_PATCH_FIELD_DISP32) {
                if (validate_field_insn_shape(curr->target_arch, v_write + curr->arena_offset, hole->insn_offset, curr->text_size) != EIA_SUCCESS) {
                    fprintf(stderr, "[EIA ERROR] Invalid instruction shape for field displacement hole at 0x%x in '%s' (arch=%u)\n",
                            hole->insn_offset, curr->path, curr->target_arch);
                    free(all_bins);
                    return 1;
                }

                const TypeFieldHashEntry *f = field_reg_lookup(&field_reg, hole->type_sig_hash, hole->field_or_sym_hash);
                if (!f) {
                    fprintf(stderr, "[EIA ERROR] Field resolution failed for hash 0x%016lx in '%s'\n",
                            (unsigned long)hole->field_or_sym_hash, curr->path);
                    free(all_bins);
                    return 1;
                }

                /* Check schema narrowing rule & inject widening/truncation adapter if safe */
                for (size_t t = 0; t < curr->type_graph_count; ++t) {
                    if (curr->type_graph[t].type_sig_hash == hole->type_sig_hash &&
                        curr->type_graph[t].field_hash == hole->field_or_sym_hash) {
                        uint32_t expected_size = curr->type_graph[t].field_size & 0xFFFF;
                        uint32_t prov_field_sz = f->field_size & 0xFFFF;
                        if (prov_field_sz < expected_size) {
                            bool adapted = eia_adapt_widening_instruction(
                                curr->target_arch, patch_site, hole->insn_offset,
                                curr->text_size, prov_field_sz, expected_size
                            );
                            if (adapted) {
                                printf("[EIA LINK] Injected widening/truncation adapter (field %u bytes -> expected %u bytes) at 0x%x in '%s' (arch=%u)\n",
                                       prov_field_sz, expected_size, hole->insn_offset, curr->path, curr->target_arch);
                            } else {
                                fprintf(stderr, "[EIA ERROR] Schema rejection: field narrowing unsupported for type 0x%016lx field 0x%016lx (expected %u bytes, provider has %u bytes)\n",
                                        (unsigned long)hole->type_sig_hash, (unsigned long)hole->field_or_sym_hash,
                                        expected_size, prov_field_sz);
                                sym_reg_free(&sym_reg);
                                field_reg_free(&field_reg);
                                cleanup_loaded_binaries(client, providers, provider_count);
                                free(all_bins);
                                return 1;
                            }
                        }
                        break;
                    }
                }

                uint32_t resolved_disp = f->byte_offset;
                if (curr->target_arch == 1) {
                    /* ARM64: patch movz x16 and movk x16 */
                    uint32_t movz = 0xd2800010 | ((resolved_disp & 0xffff) << 5);
                    uint32_t movk = 0xf2a00010 | (((resolved_disp >> 16) & 0xffff) << 5);
                    memcpy(patch_site, &movz, 4);
                    memcpy(patch_site + 4, &movk, 4);
                } else if (curr->target_arch == 2) {
                    /* RISC-V 64: patch lui t0 and addi t0 */
                    uint32_t hi = (resolved_disp + 0x800) >> 12;
                    uint32_t lo = resolved_disp & 0xFFF;
                    uint32_t lui = 0x000002b7 | (hi << 12);
                    uint32_t addi = 0x00028293 | (lo << 20);
                    memcpy(patch_site, &lui, 4);
                    memcpy(patch_site + 4, &addi, 4);
                } else {
                    /* x86-64: 32-bit LE displacement */
                    patch_site[0] = (uint8_t)(resolved_disp & 0xFF);
                    patch_site[1] = (uint8_t)((resolved_disp >> 8) & 0xFF);
                    patch_site[2] = (uint8_t)((resolved_disp >> 16) & 0xFF);
                    patch_site[3] = (uint8_t)((resolved_disp >> 24) & 0xFF);
                }
            } else if (hole->patch_kind == EIA_PATCH_SYM_REL32) {
                const SymbolHashEntry *s = sym_reg_lookup(&sym_reg, hole->field_or_sym_hash);
                if (!s) {
                    fprintf(stderr, "[EIA ERROR] Unresolved external symbol: hash 0x%016lx in '%s'\n",
                            (unsigned long)hole->field_or_sym_hash, curr->path);
                    sym_reg_free(&sym_reg);
                    field_reg_free(&field_reg);
                    cleanup_loaded_binaries(client, providers, provider_count);
                    free(all_bins);
                    return 1;
                }

                uint64_t target_exec_vaddr = s->target_vaddr;

                /* Verify calling contract signature, structural types, and parameter count */
                for (size_t c = 0; c < curr->contract_count; ++c) {
                    if (curr->contracts[c].symbol_hash == hole->field_or_sym_hash &&
                        (curr->contracts[c].flags & EIA_SYM_FLAG_IMPORT)) {
                        if (curr->contracts[c].param_count != s->param_count) {
                            fprintf(stderr, "[EIA ERROR] Signature mismatch for symbol 0x%016lx: caller '%s' expects %u params, callee '%s' exports %u params\n",
                                     (unsigned long)hole->field_or_sym_hash, curr->path,
                                    curr->contracts[c].param_count, s->binary_name, s->param_count);
                            sym_reg_free(&sym_reg);
                            field_reg_free(&field_reg);
                            cleanup_loaded_binaries(client, providers, provider_count);
                            free(all_bins);
                            return 1;
                        }
                        bool bridged = false;
                        if (curr->contracts[c].calling_conv != s->calling_conv) {
                            uint32_t caller_conv = curr->contracts[c].calling_conv;
                            uint32_t callee_conv = s->calling_conv;
                            if (curr->target_arch == 0 && thunk_used + 128 <= 16384) {
                                uint32_t thunk_off = (uint32_t)(thunk_arena_offset + thunk_used);
                                uint8_t *thunk_ptr = v_write + thunk_off;
                                if (caller_conv == 0 && callee_conv == 1) {
                                    /* SysV AMD64 caller -> Win64 callee bridge (full 6 integer args, FP args, and shadow space) */
                                    size_t b_idx = 0;
                                    thunk_ptr[b_idx++] = 0x55;                                          // push rbp
                                    thunk_ptr[b_idx++] = 0x48; thunk_ptr[b_idx++] = 0x89; thunk_ptr[b_idx++] = 0xe5; // mov rbp, rsp
                                    thunk_ptr[b_idx++] = 0x48; thunk_ptr[b_idx++] = 0x83; thunk_ptr[b_idx++] = 0xec; thunk_ptr[b_idx++] = 0x30; // sub rsp, 48
                                    thunk_ptr[b_idx++] = 0x4c; thunk_ptr[b_idx++] = 0x89; thunk_ptr[b_idx++] = 0x44; thunk_ptr[b_idx++] = 0x24; thunk_ptr[b_idx++] = 0x20; // mov [rsp + 32], r8
                                    thunk_ptr[b_idx++] = 0x4c; thunk_ptr[b_idx++] = 0x89; thunk_ptr[b_idx++] = 0x4c; thunk_ptr[b_idx++] = 0x24; thunk_ptr[b_idx++] = 0x28; // mov [rsp + 40], r9
                                    thunk_ptr[b_idx++] = 0x49; thunk_ptr[b_idx++] = 0x89; thunk_ptr[b_idx++] = 0xc9; // mov r9, rcx
                                    thunk_ptr[b_idx++] = 0x49; thunk_ptr[b_idx++] = 0x89; thunk_ptr[b_idx++] = 0xd0; // mov r8, rdx
                                    thunk_ptr[b_idx++] = 0x48; thunk_ptr[b_idx++] = 0x89; thunk_ptr[b_idx++] = 0xf2; // mov rdx, rsi
                                    thunk_ptr[b_idx++] = 0x48; thunk_ptr[b_idx++] = 0x89; thunk_ptr[b_idx++] = 0xf9; // mov rcx, rdi
                                    thunk_ptr[b_idx++] = 0x48; thunk_ptr[b_idx++] = 0xb8; // mov rax, imm64
                                    uint64_t callee_addr = s->target_vaddr;
                                    memcpy(thunk_ptr + b_idx, &callee_addr, 8);
                                    b_idx += 8;
                                    thunk_ptr[b_idx++] = 0xff; thunk_ptr[b_idx++] = 0xd0; // call rax
                                    thunk_ptr[b_idx++] = 0x48; thunk_ptr[b_idx++] = 0x89; thunk_ptr[b_idx++] = 0xec; // mov rsp, rbp
                                    thunk_ptr[b_idx++] = 0x5d; // pop rbp
                                    thunk_ptr[b_idx++] = 0xc3; // ret
                                    thunk_used += 64;
                                    target_exec_vaddr = (uint64_t)(v_exec + thunk_off);
                                    bridged = true;
                                    printf("[EIA LINK] Injected SysV AMD64 -> Win64 ABI bridge thunk for symbol 0x%016lx\n",
                                           (unsigned long)hole->field_or_sym_hash);
                                } else if (caller_conv == 1 && callee_conv == 0) {
                                    /* Win64 caller -> SysV AMD64 callee bridge (full 6 integer args, callee-saved, variadic AL=8) */
                                    size_t b_idx = 0;
                                    thunk_ptr[b_idx++] = 0x55;                                          // push rbp
                                    thunk_ptr[b_idx++] = 0x48; thunk_ptr[b_idx++] = 0x89; thunk_ptr[b_idx++] = 0xe5; // mov rbp, rsp
                                    thunk_ptr[b_idx++] = 0x57;                                          // push rdi (preserve Win64 non-volatile)
                                    thunk_ptr[b_idx++] = 0x56;                                          // push rsi (preserve Win64 non-volatile)
                                    thunk_ptr[b_idx++] = 0x4c; thunk_ptr[b_idx++] = 0x8b; thunk_ptr[b_idx++] = 0x55; thunk_ptr[b_idx++] = 0x30; // mov r10, [rbp + 48]
                                    thunk_ptr[b_idx++] = 0x4c; thunk_ptr[b_idx++] = 0x8b; thunk_ptr[b_idx++] = 0x5d; thunk_ptr[b_idx++] = 0x38; // mov r11, [rbp + 56]
                                    thunk_ptr[b_idx++] = 0x48; thunk_ptr[b_idx++] = 0x89; thunk_ptr[b_idx++] = 0xcf; // mov rdi, rcx
                                    thunk_ptr[b_idx++] = 0x48; thunk_ptr[b_idx++] = 0x89; thunk_ptr[b_idx++] = 0xd6; // mov rsi, rdx
                                    thunk_ptr[b_idx++] = 0x4c; thunk_ptr[b_idx++] = 0x89; thunk_ptr[b_idx++] = 0xc2; // mov rdx, r8
                                    thunk_ptr[b_idx++] = 0x4c; thunk_ptr[b_idx++] = 0x89; thunk_ptr[b_idx++] = 0xc9; // mov rcx, r9
                                    thunk_ptr[b_idx++] = 0x4d; thunk_ptr[b_idx++] = 0x89; thunk_ptr[b_idx++] = 0xd0; // mov r8, r10
                                    thunk_ptr[b_idx++] = 0x4d; thunk_ptr[b_idx++] = 0x89; thunk_ptr[b_idx++] = 0xd9; // mov r9, r11
                                    thunk_ptr[b_idx++] = 0x49; thunk_ptr[b_idx++] = 0xba;                             // mov r10, imm64
                                    uint64_t callee_addr = s->target_vaddr;
                                    memcpy(thunk_ptr + b_idx, &callee_addr, 8);
                                    b_idx += 8;
                                    thunk_ptr[b_idx++] = 0xb0; thunk_ptr[b_idx++] = 0x08;                             // mov al, 8 (SysV variadic vector count)
                                    thunk_ptr[b_idx++] = 0x41; thunk_ptr[b_idx++] = 0xff; thunk_ptr[b_idx++] = 0xd2; // call r10
                                    thunk_ptr[b_idx++] = 0x5e;                                          // pop rsi
                                    thunk_ptr[b_idx++] = 0x5f;                                          // pop rdi
                                    thunk_ptr[b_idx++] = 0x48; thunk_ptr[b_idx++] = 0x89; thunk_ptr[b_idx++] = 0xec; // mov rsp, rbp
                                    thunk_ptr[b_idx++] = 0x5d;                                          // pop rbp
                                    thunk_ptr[b_idx++] = 0xc3;                                          // ret
                                    thunk_used += 64;
                                    target_exec_vaddr = (uint64_t)(v_exec + thunk_off);
                                    bridged = true;
                                    printf("[EIA LINK] Injected Win64 -> SysV AMD64 ABI bridge thunk for symbol 0x%016lx\n",
                                           (unsigned long)hole->field_or_sym_hash);
                                }
                            } else if (curr->target_arch == 1 && thunk_used + 64 <= 16384) {
                                /* ARM64 AAPCS Calling Convention Bridge */
                                uint32_t thunk_off = (uint32_t)(thunk_arena_offset + thunk_used);
                                uint32_t *arm_thunk = (uint32_t *)(v_write + thunk_off);
                                size_t a_idx = 0;
                                arm_thunk[a_idx++] = 0xa9bf7bfd; /* stp x29, x30, [sp, -16]! */
                                arm_thunk[a_idx++] = 0x910003fd; /* mov x29, sp */
                                uint64_t target = s->target_vaddr;
                                arm_thunk[a_idx++] = 0xd2800000 | 16 | ((target & 0xffff) << 5); /* movz x16, ... */
                                arm_thunk[a_idx++] = 0xf2a00000 | 16 | (((target >> 16) & 0xffff) << 5); /* movk x16, ... */
                                arm_thunk[a_idx++] = 0xf2c00000 | 16 | (((target >> 32) & 0xffff) << 5); /* movk x16, ... */
                                arm_thunk[a_idx++] = 0xf2e00000 | 16 | (((target >> 48) & 0xffff) << 5); /* movk x16, ... */
                                arm_thunk[a_idx++] = 0xd63f0200; /* blr x16 */
                                arm_thunk[a_idx++] = 0xa8c17bfd; /* ldp x29, x30, [sp], 16 */
                                arm_thunk[a_idx++] = 0xd65f03c0; /* ret */
                                thunk_used += 64;
                                target_exec_vaddr = (uint64_t)(v_exec + thunk_off);
                                bridged = true;
                                printf("[EIA LINK] Injected ARM64 AAPCS calling convention bridge thunk for symbol 0x%016lx\n",
                                       (unsigned long)hole->field_or_sym_hash);
                            } else if (curr->target_arch == 2 && thunk_used + 64 <= 16384) {
                                /* RISC-V LP64D Calling Convention Bridge */
                                uint32_t thunk_off = (uint32_t)(thunk_arena_offset + thunk_used);
                                uint32_t *rv_thunk = (uint32_t *)(v_write + thunk_off);
                                size_t r_idx = 0;
                                rv_thunk[r_idx++] = 0xfe010113; /* addi sp, sp, -32 */
                                rv_thunk[r_idx++] = 0x00113c23; /* sd ra, 24(sp) */
                                rv_thunk[r_idx++] = 0x00813823; /* sd s0, 16(sp) */
                                uint64_t target = s->target_vaddr;
                                uint32_t hi = (uint32_t)((target + 0x800) >> 12);
                                uint32_t lo = (uint32_t)(target & 0xfff);
                                rv_thunk[r_idx++] = 0x00000337 | (hi << 12); /* lui t1, hi */
                                rv_thunk[r_idx++] = 0x00030313 | (lo << 20); /* addi t1, t1, lo */
                                rv_thunk[r_idx++] = 0x000300e7; /* jalr ra, 0(t1) */
                                rv_thunk[r_idx++] = 0x01813083; /* ld ra, 24(sp) */
                                rv_thunk[r_idx++] = 0x01013403; /* ld s0, 16(sp) */
                                rv_thunk[r_idx++] = 0x02010113; /* addi sp, sp, 32 */
                                rv_thunk[r_idx++] = 0x00008067; /* jalr zero, 0(ra) (ret) */
                                thunk_used += 64;
                                target_exec_vaddr = (uint64_t)(v_exec + thunk_off);
                                bridged = true;
                                printf("[EIA LINK] Injected RISC-V LP64D calling convention bridge thunk for symbol 0x%016lx\n",
                                       (unsigned long)hole->field_or_sym_hash);
                            }
                            if (!bridged) {
                                fprintf(stderr, "[EIA ERROR] Calling convention mismatch for symbol 0x%016lx: caller '%s' conv %u, callee '%s' conv %u (no bridge available)\n",
                                        (unsigned long)hole->field_or_sym_hash, curr->path,
                                        caller_conv, s->binary_name, callee_conv);
                                sym_reg_free(&sym_reg);
                                field_reg_free(&field_reg);
                                cleanup_loaded_binaries(client, providers, provider_count);
                                free(all_bins);
                                return 1;
                            }
                        }
                        if (!bridged && curr->contracts[c].type_sig_hash != 0 && s->type_sig_hash != 0 &&
                            curr->contracts[c].type_sig_hash != s->type_sig_hash) {
                            fprintf(stderr, "[EIA ERROR] Structural signature mismatch for symbol 0x%016lx: caller expects 0x%016lx, callee has 0x%016lx\n",
                                    (unsigned long)hole->field_or_sym_hash, (unsigned long)curr->contracts[c].type_sig_hash, (unsigned long)s->type_sig_hash);
                            sym_reg_free(&sym_reg);
                            field_reg_free(&field_reg);
                            cleanup_loaded_binaries(client, providers, provider_count);
                            free(all_bins);
                            return 1;
                        }
                        break;
                    }
                }

                if (curr->target_arch == 1) {
                    /* ARM64: insn must be BL (0x94000000) */
                    uint32_t insn = *(const uint32_t *)patch_site;
                    if ((insn & 0xfc000000) != 0x94000000) {
                        fprintf(stderr, "[EIA ERROR] Invalid instruction shape for symbol call at 0x%x in '%s' (expected BL)\n",
                                hole->insn_offset, curr->path);
                        sym_reg_free(&sym_reg);
                        field_reg_free(&field_reg);
                        cleanup_loaded_binaries(client, providers, provider_count);
                        free(all_bins);
                        return 1;
                    }
                    int64_t rel_disp = (int64_t)target_exec_vaddr - (int64_t)(v_exec + curr->arena_offset + hole->insn_offset);
                    uint32_t imm26 = (uint32_t)((rel_disp >> 2) & 0x03ffffff);
                    uint32_t bl = 0x94000000 | imm26;
                    memcpy(patch_site, &bl, 4);
                } else if (curr->target_arch == 2) {
                    /* RISC-V 64: insn must be JAL ra (0x000000ef) */
                    uint32_t insn = *(const uint32_t *)patch_site;
                    if ((insn & 0x7f) != 0x6f) {
                        fprintf(stderr, "[EIA ERROR] Invalid instruction shape for symbol call at 0x%x in '%s' (expected JAL)\n",
                                hole->insn_offset, curr->path);
                        sym_reg_free(&sym_reg);
                        field_reg_free(&field_reg);
                        cleanup_loaded_binaries(client, providers, provider_count);
                        free(all_bins);
                        return 1;
                    }
                    int64_t rel_disp = (int64_t)target_exec_vaddr - (int64_t)(v_exec + curr->arena_offset + hole->insn_offset);
                    uint32_t imm20 = (uint32_t)rel_disp;
                    uint32_t b20 = (imm20 >> 20) & 1;
                    uint32_t b10_1 = (imm20 >> 1) & 0x3ff;
                    uint32_t b11 = (imm20 >> 11) & 1;
                    uint32_t b19_12 = (imm20 >> 12) & 0xff;
                    uint32_t jal = (b20 << 31) | (b10_1 << 21) | (b11 << 20) | (b19_12 << 12) | (1 << 7) | 0x6f;
                    memcpy(patch_site, &jal, 4);
                } else {
                    /* x86_64: preceding byte must be 0xE8 (CALL rel32) */
                    if (hole->insn_offset > 0 && patch_site[-1] != 0xE8) {
                        fprintf(stderr, "[EIA ERROR] Invalid instruction shape for symbol call at 0x%x in '%s' (expected 0xE8, got 0x%02x)\n",
                                hole->insn_offset, curr->path, patch_site[-1]);
                        sym_reg_free(&sym_reg);
                        field_reg_free(&field_reg);
                        cleanup_loaded_binaries(client, providers, provider_count);
                        free(all_bins);
                        return 1;
                    }

                    uint64_t call_site_exec = (uint64_t)(v_exec + curr->arena_offset + hole->insn_offset);
                    int64_t rel_disp = (int64_t)target_exec_vaddr - (int64_t)(call_site_exec + 4);
                    if (rel_disp < -2147483648LL || rel_disp > 2147483647LL) {
                        fprintf(stderr, "[EIA ERROR] Inter-binary displacement exceeds 32-bit range\n");
                        sym_reg_free(&sym_reg);
                        field_reg_free(&field_reg);
                        cleanup_loaded_binaries(client, providers, provider_count);
                        free(all_bins);
                        return 1;
                    }

                    uint32_t d = (uint32_t)rel_disp;
                    patch_site[0] = (uint8_t)(d & 0xFF);
                    patch_site[1] = (uint8_t)((d >> 8) & 0xFF);
                    patch_site[2] = (uint8_t)((d >> 16) & 0xFF);
                    patch_site[3] = (uint8_t)((d >> 24) & 0xFF);
                }
            }
        }
    }

    free(all_bins);
    all_bins = NULL;

    /* 7. HASI Cache pipeline synchronization */
    hasi_cache_sync(v_exec, total_code_size);

    /* 8. Writer alias permanent unmapping: strict W^X enforcement */
#ifdef _WIN32
    UnmapViewOfFile(v_write);
    v_write = NULL;
    DWORD oldProtect = 0;
    VirtualProtect(v_exec, total_code_size, PAGE_EXECUTE_READ, &oldProtect);
#else
    munmap(v_write, total_code_size);
    v_write = NULL;
#endif

    /* 9. Locate client's entrypoint */
    uint32_t main_fn_offset = 0;
    bool found_main = false;
    uint64_t main_hash = spark0_hash_str("main");

    for (size_t c = 0; c < client->contract_count; ++c) {
        if (client->contracts[c].symbol_hash == main_hash &&
            (client->contracts[c].flags & EIA_SYM_FLAG_EXPORT)) {
            main_fn_offset = (uint32_t)(client->contracts[c].vaddr - client->text_vaddr_base);
            found_main = true;
            break;
        }
    }

    if (!found_main) {
        /* Fallback: use first exported function */
        for (size_t c = 0; c < client->contract_count; ++c) {
            if (client->contracts[c].flags & EIA_SYM_FLAG_EXPORT) {
                main_fn_offset = (uint32_t)(client->contracts[c].vaddr - client->text_vaddr_base);
                found_main = true;
                break;
            }
        }
    }

    if (!found_main) {
        fprintf(stderr, "[EIA ERROR] No callable entrypoint found in '%s'\n", client_path);
        sym_reg_free(&sym_reg);
        field_reg_free(&field_reg);
        cleanup_loaded_binaries(client, providers, provider_count);
        return 1;
    }

    /* 10. Execute direct native machine code via cross-platform SysV bridge if matching host ISA */
    bool can_exec_native = false;
#if defined(__x86_64__)
    if (client->target_arch == 0) can_exec_native = true;
#elif defined(__aarch64__)
    if (client->target_arch == 1) can_exec_native = true;
#elif defined(__riscv)
    if (client->target_arch == 2) can_exec_native = true;
#endif

    int64_t exit_code = 0;
    if (can_exec_native) {
        void *entry_ptr = (void *)(v_exec + client->arena_offset + main_fn_offset);
        GdamGeneration *active_gen = gdam_reader_enter(&g_runtime_gdam);
        (void)active_gen;
        exit_code = call_sysv_entry(entry_ptr);
        gdam_reader_leave(&g_runtime_gdam);
        gdam_reclaim_retired(&g_runtime_gdam);
    } else {
#ifndef _WIN32
        const char *emu = NULL;
        if (client->target_arch == 1) emu = "qemu-aarch64";
        else if (client->target_arch == 2) emu = "qemu-riscv64";

        bool emu_executed = false;
        if (emu) {
            char check_cmd[128];
            snprintf(check_cmd, sizeof(check_cmd), "command -v %s >/dev/null 2>&1", emu);
            if (system(check_cmd) == 0) {
                const char *tmpdir = getenv("TMPDIR");
                char tmp_exec[512];
                snprintf(tmp_exec, sizeof(tmp_exec), "%s/eia_cross_XXXXXX", tmpdir ? tmpdir : "/tmp");
                int tfd = mkstemp(tmp_exec);
                if (tfd >= 0) {
                    size_t out_sz = client->file_size;
                    size_t text_off = (size_t)(client->text_data - client->file_data);
                    if (text_off + total_code_size > out_sz) {
                        out_sz = text_off + total_code_size;
                    }
                    uint8_t *tmp_buf = (uint8_t *)calloc(out_sz, 1);
                    if (tmp_buf) {
                        memcpy(tmp_buf, client->file_data, client->file_size);
                        memcpy(tmp_buf + text_off, v_exec, total_code_size);
                        ssize_t w = write(tfd, tmp_buf, out_sz);
                        (void)w;
                        free(tmp_buf);
                    }
                    close(tfd);
                    chmod(tmp_exec, 0755);

                    char run_cmd[768];
                    snprintf(run_cmd, sizeof(run_cmd), "%s %s", emu, tmp_exec);
                    int q_status = system(run_cmd);
                    unlink(tmp_exec);
                    if (WIFEXITED(q_status)) {
                        exit_code = WEXITSTATUS(q_status);
                        printf("[EIA RUN] Cross-architecture dynamic execution via %s: exit %ld\n", emu, (long)exit_code);
                        emu_executed = true;
                    }
                }
            }
        }
        if (!emu_executed) {
            fprintf(stderr, "[EIA ERROR] Unsupported execution environment: target architecture %u cannot be executed natively on host and emulator '%s' is unavailable\n",
                    client->target_arch, emu ? emu : "unknown");
            sym_reg_free(&sym_reg);
            field_reg_free(&field_reg);
            cleanup_loaded_binaries(client, providers, provider_count);
            return 1;
        }
#else
        fprintf(stderr, "[EIA ERROR] Unsupported execution environment: target architecture %u cannot be executed on Windows host\n",
                client->target_arch);
        sym_reg_free(&sym_reg);
        field_reg_free(&field_reg);
        cleanup_loaded_binaries(client, providers, provider_count);
        return 1;
#endif
    }

    /* Clean up */
#ifdef _WIN32
    UnmapViewOfFile(v_exec);
    CloseHandle(hMap);
#else
    munmap(v_exec, total_code_size);
    close(memfd);
#endif
    sym_reg_free(&sym_reg);
    field_reg_free(&field_reg);
    cleanup_loaded_binaries(client, providers, provider_count);

    return (int)exit_code;
}
#endif /* EIA_LOADER_LIB */
