/*
 * include/gdam.h - EIA Generation-Driven Schema Migration (GDAM) Public Runtime API
 *
 * Provides thread-safe, zero-downtime hot migration for application state.
 *
 * Capabilities & Lifecycle:
 * 1. Thread Registration: Threads cooperatively participate in epochs using safe-points.
 * 2. Object Graph Tracking: Pointers to application structs/arrays are registered with type hashes.
 * 3. Atomic Publication: Migrations transition generations atomically with sequential consistency.
 * 4. Cooperative Safe-Points: Readers enter/leave safe-points without locks; writers synchronize via RCU-like reclamation.
 * 5. Rollback Protection: If invariant checks fail during staging or migration, state rolls back cleanly.
 * 6. Kernel Handle Migration: Live file descriptors, socket pairs, and stream channels are cloned,
 *    rebound, and transferred across schema epochs and processes via SCM_RIGHTS without in-flight data loss.
 */

#ifndef EIA_GDAM_H
#define EIA_GDAM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdatomic.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "spark0.h"

/* Status codes */
#define GDAM_SUCCESS            0
#define GDAM_ERR_INVALID_ARG   -1
#define GDAM_ERR_BUSY          -2
#define GDAM_ERR_NO_MEMORY     -3
#define GDAM_ERR_ROLLBACK      -4
#define GDAM_ERR_EPOCH_MISMATCH -5

/* Kernel Handle Resource Types */
#define GDAM_RES_FILE_DESC   1
#define GDAM_RES_UNIX_SOCKET 2
#define GDAM_RES_INET_SOCKET 3

typedef struct GdamKernelResource {
    int resource_type;          /* GDAM_RES_FILE_DESC, GDAM_RES_UNIX_SOCKET, etc. */
    int fd;                     /* Active file descriptor */
    int flags;                  /* fcntl flags (e.g. O_RDWR, O_NONBLOCK) */
    int64_t seek_offset;        /* Exact file seek position */
    int socket_family;          /* AF_UNIX or AF_INET */
    int socket_type;            /* SOCK_STREAM or SOCK_DGRAM */
    uint64_t epoch;             /* Associated epoch */
    struct GdamKernelResource *next;
} GdamKernelResource;

/* Runtime Lifecycle API */
int gdam_runtime_init(ConcurrentGdamState *gdam, GdamGeneration *init_gen);
int gdam_runtime_shutdown(ConcurrentGdamState *gdam);

/* Thread Registration & Safe-Points */
int gdam_thread_register(ConcurrentGdamState *gdam, uint64_t tid);
int gdam_thread_unregister(ConcurrentGdamState *gdam, uint64_t tid);
void gdam_safepoint_enter(ConcurrentGdamState *gdam, uint64_t tid);
void gdam_safepoint_leave(ConcurrentGdamState *gdam, uint64_t tid);

/* Application Object Graph Registration */
int gdam_object_register(ConcurrentGdamState *gdam, void **obj_ref, uint64_t type_hash, size_t count, size_t elem_size);
int gdam_object_unregister(ConcurrentGdamState *gdam, void **obj_ref);
int gdam_publish_pointer(ConcurrentGdamState *gdam, void **obj_ref, void *new_ptr);

/* Generational Migration Lifecycle */
int gdam_stage_migration(ConcurrentGdamState *gdam, GdamGeneration *next_gen);
uint64_t gdam_commit_migration(ConcurrentGdamState *gdam, GdamGeneration *new_gen, uint64_t type_hash);
int gdam_abort_migration(ConcurrentGdamState *gdam);

/* Kernel Handle & Stream Socket Migration */
int gdam_register_kernel_handle(ConcurrentGdamState *gdam, int fd, int resource_type);
int gdam_migrate_kernel_handle(ConcurrentGdamState *gdam, int old_fd, int *new_fd_out);
int gdam_unregister_kernel_handle(ConcurrentGdamState *gdam, int fd);

/* Cross-Process Zero-Downtime FD Handoff via SCM_RIGHTS */
int gdam_send_fd_scm_rights(int unix_sock, int fd_to_send);
int gdam_recv_fd_scm_rights(int unix_sock, int *fd_received_out);

#ifdef __cplusplus
}
#endif

#endif /* EIA_GDAM_H */
