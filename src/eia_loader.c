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
#endif
#include "spark0.h"

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

static uint64_t blake3_hash64(const uint8_t *buf, size_t len) {
    if (len <= 1024) {
        uint8_t root_cv[32];
        blake3_hash_chunk(buf, len, 0, 1, root_cv);
        uint64_t low = (uint64_t)get_u32(root_cv, 0);
        uint64_t high = (uint64_t)get_u32(root_cv, 1);
        return low | (high << 32);
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

    uint64_t low = (uint64_t)get_u32(cv_list[0], 0);
    uint64_t high = (uint64_t)get_u32(cv_list[0], 1);
    free(cv_list);
    return low | (high << 32);
}

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
} LoadedBinary;

#define HASH_TABLE_CAP 4096

/* Symbol export hash table entry */
typedef struct {
    uint64_t symbol_hash;
    uint64_t target_vaddr; /* Virtual address in v_exec mapping */
    uint16_t param_count;
    uint16_t calling_conv;
    const char *binary_name;
    bool occupied;
} SymbolHashEntry;

/* Type graph field hash table entry */
typedef struct {
    uint64_t type_sig_hash;
    uint64_t field_hash;
    uint32_t byte_offset;
    uint32_t field_size;
    bool occupied;
} TypeFieldHashEntry;

static inline size_t hash_field_key(uint64_t type_hash, uint64_t field_hash) {
    uint64_t k = type_hash ^ (field_hash * 0x100000001b3ULL);
    k ^= (k >> 33);
    k *= 0xff51afd7ed558ccdULL;
    k ^= (k >> 33);
    return (size_t)(k & (HASH_TABLE_CAP - 1));
}

static void insert_type_field(TypeFieldHashEntry *table, uint64_t type_hash, uint64_t field_hash, uint32_t offset, uint32_t size) {
    size_t idx = hash_field_key(type_hash, field_hash);
    for (size_t step = 0; step < HASH_TABLE_CAP; ++step) {
        size_t i = (idx + step) & (HASH_TABLE_CAP - 1);
        if (!table[i].occupied || (table[i].type_sig_hash == type_hash && table[i].field_hash == field_hash)) {
            table[i].type_sig_hash = type_hash;
            table[i].field_hash = field_hash;
            table[i].byte_offset = offset;
            table[i].field_size = size;
            table[i].occupied = true;
            return;
        }
    }
}

static const TypeFieldHashEntry *lookup_type_field(const TypeFieldHashEntry *table, uint64_t type_hash, uint64_t field_hash) {
    size_t idx = hash_field_key(type_hash, field_hash);
    for (size_t step = 0; step < HASH_TABLE_CAP; ++step) {
        size_t i = (idx + step) & (HASH_TABLE_CAP - 1);
        if (!table[i].occupied) return NULL;
        if (table[i].type_sig_hash == type_hash && table[i].field_hash == field_hash) {
            return &table[i];
        }
    }
    return NULL;
}

static inline size_t hash_sym_key(uint64_t sym_hash) {
    uint64_t k = sym_hash ^ (sym_hash >> 33);
    k *= 0xff51afd7ed558ccdULL;
    k ^= (k >> 33);
    return (size_t)(k & (HASH_TABLE_CAP - 1));
}

static void insert_exported_symbol(SymbolHashEntry *table, uint64_t sym_hash, uint64_t target_vaddr, uint16_t param_cnt, uint16_t cconv, const char *bin_name) {
    size_t idx = hash_sym_key(sym_hash);
    for (size_t step = 0; step < HASH_TABLE_CAP; ++step) {
        size_t i = (idx + step) & (HASH_TABLE_CAP - 1);
        if (!table[i].occupied || table[i].symbol_hash == sym_hash) {
            table[i].symbol_hash = sym_hash;
            table[i].target_vaddr = target_vaddr;
            table[i].param_count = param_cnt;
            table[i].calling_conv = cconv;
            table[i].binary_name = bin_name;
            table[i].occupied = true;
            return;
        }
    }
}

static const SymbolHashEntry *lookup_exported_symbol(const SymbolHashEntry *table, uint64_t sym_hash) {
    size_t idx = hash_sym_key(sym_hash);
    for (size_t step = 0; step < HASH_TABLE_CAP; ++step) {
        size_t i = (idx + step) & (HASH_TABLE_CAP - 1);
        if (!table[i].occupied) return NULL;
        if (table[i].symbol_hash == sym_hash) return &table[i];
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
    (void)addr; (void)size;
    __asm__ __volatile__("dsb ish; isb" ::: "memory");
#elif defined(__riscv)
    (void)addr; (void)size;
    __asm__ __volatile__("fence.i" ::: "memory");
#else
    __builtin___clear_cache((char *)addr, (char *)addr + size);
#endif
}

/* Instruction shape validation: ensures patch site is an LEA or MOV memory disp32 */
static int validate_field_insn_shape(const uint8_t *code, uint32_t insn_offset) {
    if (insn_offset >= 3) {
        uint8_t op = code[insn_offset - 2];
        uint8_t modrm = code[insn_offset - 1];
        if ((op == 0x8D || op == 0x8B || op == 0x89) && ((modrm & 0xC0) == 0x80)) {
            return EIA_SUCCESS;
        }
    }
    if (insn_offset >= 4) {
        uint8_t op = code[insn_offset - 3];
        uint8_t modrm = code[insn_offset - 2];
        if ((op == 0x8D || op == 0x8B || op == 0x89) && ((modrm & 0xC0) == 0x80)) {
            return EIA_SUCCESS;
        }
    }
    return EIA_ERR_BAD_INSN;
}

static int cmp_u32(const void *a, const void *b) {
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

static LoadedBinary *load_binary(const char *path) {
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

    /* Locate .text section (starts at offset 0x10000 in standard ELF output) */
    size_t text_off = 0x10000;
    if (text_off < sz) {
        b->text_data = data + text_off;
        b->text_size = sz - text_off;
    } else {
        b->text_data = data;
        b->text_size = sz;
    }

    return b;
}

/* ========================================================================= */
/*                               MAIN LOADER                                 */
/* ========================================================================= */

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <client_binary> [provider_binary ...]\n", argv[0]);
        fprintf(stderr, "EIA Dynamic Linker-Loader & Dual Virtual Alias Mapping Substrate\n");
        return 1;
    }

    const char *client_path = argv[1];
    int provider_count = argc - 2;

    /* 1. Load client binary */
    LoadedBinary *client = load_binary(client_path);
    if (!client) return 1;

    /* 2. Load provider binaries */
    LoadedBinary **providers = NULL;
    if (provider_count > 0) {
        providers = (LoadedBinary **)calloc(provider_count, sizeof(LoadedBinary *));
        for (int i = 0; i < provider_count; ++i) {
            providers[i] = load_binary(argv[2 + i]);
            if (!providers[i]) {
                fprintf(stderr, "[EIA ERROR] Failed to load provider artifact '%s'\n", argv[2 + i]);
                return 1;
            }
        }
    }

    /* 3. Compute required DVAM arena size */
    size_t total_code_size = (client->text_size + 0xFFF) & ~0xFFFULL;
    client->arena_offset = 0;

    for (int i = 0; i < provider_count; ++i) {
        providers[i]->arena_offset = total_code_size;
        total_code_size += (providers[i]->text_size + 0xFFF) & ~0xFFFULL;
    }

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

    /* 5. Build Global Export Catalog & Global Type Graph Index (O(1) Hash Tables) */
    static SymbolHashEntry sym_table[HASH_TABLE_CAP];
    memset(sym_table, 0, sizeof(sym_table));

    static TypeFieldHashEntry field_table[HASH_TABLE_CAP];
    memset(field_table, 0, sizeof(field_table));

    /* Register provider exports and type graph entries */
    for (int p = 0; p < provider_count; ++p) {
        LoadedBinary *pb = providers[p];

        /* Symbol contracts */
        for (size_t c = 0; c < pb->contract_count; ++c) {
            const SymbolContract *sc = &pb->contracts[c];
            if (sc->flags & EIA_SYM_FLAG_EXPORT) {
                uint32_t fn_offset = (uint32_t)(sc->vaddr - 0x410000);
                uint64_t target_vaddr = (uint64_t)(v_exec + pb->arena_offset + fn_offset);
                insert_exported_symbol(sym_table, sc->symbol_hash, target_vaddr, sc->param_count, sc->calling_conv, pb->path);
            }
        }

        /* Type graph */
        for (size_t t = 0; t < pb->type_graph_count; ++t) {
            const EiaTypeGraphEntry *tge = &pb->type_graph[t];
            insert_type_field(field_table, tge->type_sig_hash, tge->field_hash, tge->byte_offset, tge->field_size);
        }
    }

    /* Also register client's own type graph entries as baseline fallback */
    for (size_t t = 0; t < client->type_graph_count; ++t) {
        const EiaTypeGraphEntry *tge = &client->type_graph[t];
        if (!lookup_type_field(field_table, tge->type_sig_hash, tge->field_hash)) {
            insert_type_field(field_table, tge->type_sig_hash, tge->field_hash, tge->byte_offset, tge->field_size);
        }
    }

    /* Check ABI epoch compatibility */
    for (int i = 0; i < provider_count; ++i) {
        if (providers[i]->holo->abi_epoch != client->holo->abi_epoch) {
            fprintf(stderr, "[EIA ERROR] Incompatible ABI epoch: client '%s' (epoch %lu) vs provider '%s' (epoch %lu)\n",
                    client->path, (unsigned long)client->holo->abi_epoch,
                    providers[i]->path, (unsigned long)providers[i]->holo->abi_epoch);
            return 1;
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
                if (validate_field_insn_shape(v_write + curr->arena_offset, hole->insn_offset) != EIA_SUCCESS) {
                    fprintf(stderr, "[EIA ERROR] Invalid instruction shape for field displacement hole at 0x%x in '%s'\n",
                            hole->insn_offset, curr->path);
                    free(all_bins);
                    return 1;
                }

                const TypeFieldHashEntry *f = lookup_type_field(field_table, hole->type_sig_hash, hole->field_or_sym_hash);
                if (!f) {
                    fprintf(stderr, "[EIA ERROR] Field resolution failed for hash 0x%016lx in '%s'\n",
                            (unsigned long)hole->field_or_sym_hash, curr->path);
                    free(all_bins);
                    return 1;
                }

                /* Check schema narrowing rule */
                for (size_t t = 0; t < curr->type_graph_count; ++t) {
                    if (curr->type_graph[t].type_sig_hash == hole->type_sig_hash &&
                        curr->type_graph[t].field_hash == hole->field_or_sym_hash) {
                        uint32_t expected_size = curr->type_graph[t].field_size;
                        if (f->field_size < expected_size) {
                            fprintf(stderr, "[EIA ERROR] Schema rejection: field narrowing unsupported for type 0x%016lx field 0x%016lx (expected %u bytes, provider has %u bytes)\n",
                                    (unsigned long)hole->type_sig_hash, (unsigned long)hole->field_or_sym_hash,
                                    expected_size, f->field_size);
                            free(all_bins);
                            return 1;
                        }
                        break;
                    }
                }

                uint32_t resolved_disp = f->byte_offset;
                patch_site[0] = (uint8_t)(resolved_disp & 0xFF);
                patch_site[1] = (uint8_t)((resolved_disp >> 8) & 0xFF);
                patch_site[2] = (uint8_t)((resolved_disp >> 16) & 0xFF);
                patch_site[3] = (uint8_t)((resolved_disp >> 24) & 0xFF);
            } else if (hole->patch_kind == EIA_PATCH_SYM_REL32) {
                const SymbolHashEntry *s = lookup_exported_symbol(sym_table, hole->field_or_sym_hash);
                if (!s) {
                    fprintf(stderr, "[EIA ERROR] Unresolved external symbol: hash 0x%016lx in '%s'\n",
                            (unsigned long)hole->field_or_sym_hash, curr->path);
                    free(all_bins);
                    return 1;
                }

                /* Verify calling contract signature and parameter count */
                for (size_t c = 0; c < curr->contract_count; ++c) {
                    if (curr->contracts[c].symbol_hash == hole->field_or_sym_hash &&
                        (curr->contracts[c].flags & EIA_SYM_FLAG_IMPORT)) {
                        if (curr->contracts[c].param_count != s->param_count) {
                            fprintf(stderr, "[EIA ERROR] Signature mismatch for symbol 0x%016lx: caller '%s' expects %u params, callee '%s' exports %u params\n",
                                    (unsigned long)hole->field_or_sym_hash, curr->path,
                                    curr->contracts[c].param_count, s->binary_name, s->param_count);
                            free(all_bins);
                            return 1;
                        }
                        if (curr->contracts[c].calling_conv != s->calling_conv) {
                            fprintf(stderr, "[EIA ERROR] Calling convention mismatch for symbol 0x%016lx: caller '%s' conv %u, callee '%s' conv %u\n",
                                    (unsigned long)hole->field_or_sym_hash, curr->path,
                                    curr->contracts[c].calling_conv, s->binary_name, s->calling_conv);
                            free(all_bins);
                            return 1;
                        }
                        break;
                    }
                }

                /* Validate instruction shape: preceding byte must be 0xE8 (CALL rel32) */
                if (hole->insn_offset > 0 && patch_site[-1] != 0xE8) {
                    fprintf(stderr, "[EIA ERROR] Invalid instruction shape for symbol call at 0x%x in '%s' (expected 0xE8, got 0x%02x)\n",
                            hole->insn_offset, curr->path, patch_site[-1]);
                    free(all_bins);
                    return 1;
                }

                uint64_t target_exec_vaddr = s->target_vaddr;
                uint64_t call_site_exec = (uint64_t)(v_exec + curr->arena_offset + hole->insn_offset);
                int64_t rel_disp = (int64_t)target_exec_vaddr - (int64_t)(call_site_exec + 4);
                if (rel_disp < -2147483648LL || rel_disp > 2147483647LL) {
                    fprintf(stderr, "[EIA ERROR] Inter-binary displacement exceeds 32-bit range\n");
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

    free(all_bins);
    all_bins = NULL;

    /* 7. HASI Cache pipeline synchronization */
    hasi_cache_sync(v_exec, total_code_size);

    /* 8. Writer alias permanent unmapping: strict W^X enforcement */
#ifdef _WIN32
    UnmapViewOfFile(v_write);
    v_write = NULL;
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
            main_fn_offset = (uint32_t)(client->contracts[c].vaddr - 0x410000);
            found_main = true;
            break;
        }
    }

    if (!found_main) {
        /* Fallback: use first exported function */
        for (size_t c = 0; c < client->contract_count; ++c) {
            if (client->contracts[c].flags & EIA_SYM_FLAG_EXPORT) {
                main_fn_offset = (uint32_t)(client->contracts[c].vaddr - 0x410000);
                found_main = true;
                break;
            }
        }
    }

    if (!found_main) {
        fprintf(stderr, "[EIA ERROR] No callable entrypoint found in '%s'\n", client_path);
        return 1;
    }

    typedef int64_t (*ClientMainFn)(void);
    ClientMainFn run_entry = (ClientMainFn)(v_exec + client->arena_offset + main_fn_offset);

    /* 10. Execute direct native machine code */
    int64_t exit_code = run_entry();

    /* Clean up */
#ifdef _WIN32
    UnmapViewOfFile(v_exec);
    CloseHandle(hMap);
#else
    munmap(v_exec, total_code_size);
    close(memfd);
#endif
    free(client->file_data);
    free(client);
    if (providers) {
        for (int i = 0; i < provider_count; ++i) {
            free(providers[i]->file_data);
            free(providers[i]);
        }
        free(providers);
    }

    return (int)exit_code;
}
