#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <assert.h>
#include "spark0_codegen.h"

static inline uint32_t rotr32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

static inline uint32_t get_u32(const uint8_t *buf, size_t idx) {
    const uint8_t *p = buf + (idx * 4);
    return ((uint32_t)p[0]) | (((uint32_t)p[1]) << 8) | (((uint32_t)p[2]) << 16) | (((uint32_t)p[3]) << 24);
}

static inline void set_u32(uint8_t *buf, size_t idx, uint32_t val) {
    uint8_t *p = buf + (idx * 4);
    p[0] = (uint8_t)(val & 0xFF);
    p[1] = (uint8_t)((val >> 8) & 0xFF);
    p[2] = (uint8_t)((val >> 16) & 0xFF);
    p[3] = (uint8_t)((val >> 24) & 0xFF);
}

static void blake3_round_g(uint8_t *state, const uint8_t *msg, uint64_t step) {
    uint64_t a_idx = 0, b_idx = 0, c_idx = 0, d_idx = 0;
    uint64_t mx_idx = step * 2;
    uint64_t my_idx = (step * 2) + 1;

    if (step == 0) { a_idx = 0; b_idx = 4; c_idx = 8;  d_idx = 12; }
    else if (step == 1) { a_idx = 1; b_idx = 5; c_idx = 9;  d_idx = 13; }
    else if (step == 2) { a_idx = 2; b_idx = 6; c_idx = 10; d_idx = 14; }
    else if (step == 3) { a_idx = 3; b_idx = 7; c_idx = 11; d_idx = 15; }
    else if (step == 4) { a_idx = 0; b_idx = 5; c_idx = 10; d_idx = 15; }
    else if (step == 5) { a_idx = 1; b_idx = 6; c_idx = 11; d_idx = 12; }
    else if (step == 6) { a_idx = 2; b_idx = 7; c_idx = 8;  d_idx = 13; }
    else if (step == 7) { a_idx = 3; b_idx = 4; c_idx = 9;  d_idx = 14; }

    uint32_t mx = get_u32(msg, mx_idx);
    uint32_t my = get_u32(msg, my_idx);

    uint32_t a = get_u32(state, a_idx);
    uint32_t b = get_u32(state, b_idx);
    uint32_t c = get_u32(state, c_idx);
    uint32_t d = get_u32(state, d_idx);

    a = a + b + mx;
    d = rotr32(d ^ a, 16);
    c = c + d;
    b = rotr32(b ^ c, 12);
    a = a + b + my;
    d = rotr32(d ^ a, 8);
    c = c + d;
    b = rotr32(b ^ c, 7);

    set_u32(state, a_idx, a);
    set_u32(state, b_idx, b);
    set_u32(state, c_idx, c);
    set_u32(state, d_idx, d);
}

static void blake3_permute_msg(uint8_t *msg) {
    uint8_t temp[64];
    for (size_t i = 0; i < 16; ++i) {
        set_u32(temp, i, get_u32(msg, i));
    }
    set_u32(msg, 0,  get_u32(temp, 2));
    set_u32(msg, 1,  get_u32(temp, 6));
    set_u32(msg, 2,  get_u32(temp, 3));
    set_u32(msg, 3,  get_u32(temp, 10));
    set_u32(msg, 4,  get_u32(temp, 7));
    set_u32(msg, 5,  get_u32(temp, 0));
    set_u32(msg, 6,  get_u32(temp, 4));
    set_u32(msg, 7,  get_u32(temp, 13));
    set_u32(msg, 8,  get_u32(temp, 1));
    set_u32(msg, 9,  get_u32(temp, 11));
    set_u32(msg, 10, get_u32(temp, 12));
    set_u32(msg, 11, get_u32(temp, 5));
    set_u32(msg, 12, get_u32(temp, 9));
    set_u32(msg, 13, get_u32(temp, 14));
    set_u32(msg, 14, get_u32(temp, 15));
    set_u32(msg, 15, get_u32(temp, 8));
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

#define EIA_SIGNER_ENABLED 1
#include "eia_ed25519.c"

static uint8_t *spark0_create_elf_buf(const CompiledUnit *unit, size_t *out_size, int is_upbp, int target_arch) {
    if (target_arch == 4) is_upbp = 1; /* UEFI executables require PE32+ COFF headers */
    /* Calculate section offsets */
    uint64_t holo_offset = is_upbp ? 1152 : 0x80;
    uint64_t contracts_offset = is_upbp ? 1248 : (holo_offset + sizeof(UniversalHologramHeader)); /* 0x80 + 96 = 0xE0 */
    uint64_t contracts_size = unit->contract_count * sizeof(SymbolContract);

    uint64_t relocs_offset = contracts_offset + contracts_size;
    uint64_t relocs_size = unit->reloc_count * sizeof(EiaRelocHole);

    uint64_t type_graph_offset = relocs_offset + relocs_size;
    uint64_t type_graph_size = unit->type_graph_count * sizeof(EiaTypeGraphEntry);

    uint64_t text_offset = (target_arch == 3 || target_arch == 8 || target_arch == 9) ? 0x1000 : 0x10000; /* Baremetal: 4KB / Native: 64KB */
    uint64_t rodata_offset = (target_arch == 3 || target_arch == 8 || target_arch == 9) ? 0x3000 : 0x30000; /* Baremetal: 12KB / Native: 192KB */
    if (text_offset + unit->text_size > rodata_offset) {
        rodata_offset = (text_offset + unit->text_size + 0xFFF) & ~0xFFFULL;
    }

    uint64_t total_file_size = rodata_offset + ((unit->rodata_size + 0xFFF) & ~0xFFFULL);
    if (total_file_size < rodata_offset + 0x1000) total_file_size = rodata_offset + 0x1000;

    uint8_t *file_buf = (uint8_t *)calloc(total_file_size, 1);
    if (!file_buf) {
        fprintf(stderr, "Failed to allocate %lu bytes for ELF output\n", (unsigned long)total_file_size);
        return NULL;
    }

    if (is_upbp) {
        const char *tramp1 = "MZ= tail +129c $0>z;chmod +x z;./z;c=$?;rm -f z;exit $c    \n";
        memcpy(file_buf, tramp1, 60);
        /* bytes 60-63: e_lfanew = 0x140 */
        file_buf[60] = 0x40;
        file_buf[61] = 0x01;
        file_buf[62] = 0;
        file_buf[63] = 0;

        /* bytes 64-127: POSIX Shell trampoline pattern data */
        memcpy(file_buf + 64, "#!/bin/sh\n", 10);
        memset(file_buf + 74, ' ', 8);
        memcpy(file_buf + 82, "tail -c+129 \"$0\">z;chmod +x z;", 30);
        memset(file_buf + 112, ' ', 3);
        memcpy(file_buf + 115, "exec ./z \"$@\"", 13);

        /* 3. ELF64 Header at elf_base = 128 (0x80) */
        uint64_t elf_base = 128;
        Elf64Header *ehdr = (Elf64Header *)(file_buf + elf_base);
        memcpy(ehdr->e_ident, "\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0", 16);
        ehdr->e_type = 2; /* ET_EXEC */
        if (target_arch == 1) {
            ehdr->e_machine = 183; /* EM_AARCH64 */
        } else if (target_arch == 2) {
            ehdr->e_machine = 243; /* EM_RISCV */
        } else {
            ehdr->e_machine = 0x3E; /* EM_X86_64 */
        }
        ehdr->e_version = 1;
        ehdr->e_entry = 0x400000 + (text_offset - 128);
        ehdr->e_phoff = 64;
        ehdr->e_ehsize = sizeof(Elf64Header);
        ehdr->e_phentsize = sizeof(Elf64ProgramHeader);
        ehdr->e_phnum = 1;
        ehdr->e_shentsize = 64;

        Elf64ProgramHeader *phdr = (Elf64ProgramHeader *)(file_buf + elf_base + 64);
        phdr->p_type = 1; /* PT_LOAD */
        phdr->p_flags = 5; /* PF_R | PF_X (Strict W^X compliance) */
        phdr->p_offset = 0;
        phdr->p_vaddr = 0x400000;
        phdr->p_paddr = 0x400000;
        phdr->p_filesz = total_file_size;
        phdr->p_memsz = (target_arch == 0) ? (total_file_size + 0x100000) : total_file_size;
        phdr->p_align = 0x1000;

        /* 4. Offset 0x140 (320): PE/COFF Headers */
        uint64_t pe_base = 320;
        memcpy(file_buf + pe_base, "PE\0\0", 4);
        file_buf[pe_base + 4] = 0x64; file_buf[pe_base + 5] = 0x86; /* AMD64 */
        file_buf[pe_base + 6] = 1; file_buf[pe_base + 7] = 0;
        file_buf[pe_base + 20] = 240; file_buf[pe_base + 21] = 0;
        file_buf[pe_base + 22] = 0x22; file_buf[pe_base + 23] = 0;

        uint64_t opt_base = pe_base + 24;
        file_buf[opt_base + 0] = 0x0B; file_buf[opt_base + 1] = 0x02; /* PE32+ */
        file_buf[opt_base + 2] = 1; file_buf[opt_base + 3] = 0;
        file_buf[opt_base + 16] = 0; file_buf[opt_base + 17] = 0; file_buf[opt_base + 18] = 1; /* 0x10000 */
        file_buf[opt_base + 20] = 0; file_buf[opt_base + 21] = 0; file_buf[opt_base + 22] = 1;
        file_buf[opt_base + 24] = 0; file_buf[opt_base + 25] = 0; file_buf[opt_base + 26] = 0;
        file_buf[opt_base + 27] = 0x40; file_buf[opt_base + 28] = 1; /* 0x140000000 */
        file_buf[opt_base + 32] = 0; file_buf[opt_base + 33] = 0x10; /* SectionAlignment = 0x1000 */
        file_buf[opt_base + 36] = 0; file_buf[opt_base + 37] = 0x10; /* FileAlignment = 0x1000 */
        /* SizeOfImage (opt_base + 56) and SizeOfHeaders (opt_base + 60) */
        uint32_t pe_image_sz = (uint32_t)((total_file_size + 0xFFF) & ~0xFFFULL);
        set_u32(file_buf, (opt_base + 56) / 4, pe_image_sz);
        set_u32(file_buf, (opt_base + 60) / 4, 0x1000); /* SizeOfHeaders = 4096 */
        file_buf[opt_base + 68] = (target_arch == 4) ? 10 : 3; /* 10: EFI_APPLICATION, 3: CUI */
        file_buf[opt_base + 69] = 0;
        set_u32(file_buf, (opt_base + 72) / 4, 0x200000); /* SizeOfStackReserve = 2MB */
        set_u32(file_buf, (opt_base + 80) / 4, 0x1000);   /* SizeOfStackCommit = 4KB */
        set_u32(file_buf, (opt_base + 88) / 4, 0x100000); /* SizeOfHeapReserve = 1MB */
        set_u32(file_buf, (opt_base + 96) / 4, 0x1000);   /* SizeOfHeapCommit = 4KB */
        set_u32(file_buf, (opt_base + 108) / 4, 16);      /* NumberOfRvaAndSizes = 16 */

        /* 5. Offset 0x200 (512): Mach-O 64-bit Headers */
        uint64_t macho_base = 512;
        file_buf[macho_base + 0] = 0xCF; file_buf[macho_base + 1] = 0xFA;
        file_buf[macho_base + 2] = 0xED; file_buf[macho_base + 3] = 0xFE; /* 0xFEEDFACF */
        file_buf[macho_base + 4] = 7; file_buf[macho_base + 5] = 0;
        file_buf[macho_base + 6] = 0; file_buf[macho_base + 7] = 1; /* X86_64 */
        file_buf[macho_base + 8] = 3; file_buf[macho_base + 9] = 0;
        file_buf[macho_base + 10] = 0; file_buf[macho_base + 11] = 0x80;
        file_buf[macho_base + 12] = 2; file_buf[macho_base + 13] = 0;
        file_buf[macho_base + 16] = 1; file_buf[macho_base + 17] = 0;
        file_buf[macho_base + 20] = 72; file_buf[macho_base + 21] = 0;
        file_buf[macho_base + 24] = 0x85; file_buf[macho_base + 25] = 0;
        file_buf[macho_base + 26] = 0x20; file_buf[macho_base + 27] = 0;

        uint64_t seg_base = macho_base + 32;
        file_buf[seg_base + 0] = 0x19;
        file_buf[seg_base + 4] = 72;
        memcpy(file_buf + seg_base + 8, "__TEXT", 6);
        file_buf[seg_base + 36] = 1;
        file_buf[seg_base + 42] = 4;
        file_buf[seg_base + 56] = 7;
        file_buf[seg_base + 60] = 7;
    } else {
        /* 1. ELF64 Header (64 bytes) */
        Elf64Header *ehdr = (Elf64Header *)file_buf;
        memcpy(ehdr->e_ident, "\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0", 16);
        ehdr->e_type = 2; /* ET_EXEC */
        if (target_arch == 1 || target_arch == 8) {
            ehdr->e_machine = 183; /* EM_AARCH64 */
        } else if (target_arch == 2 || target_arch == 9) {
            ehdr->e_machine = 243; /* EM_RISCV */
        } else {
            ehdr->e_machine = 0x3E; /* EM_X86_64 */
        }
        ehdr->e_version = 1;
        ehdr->e_entry = unit->entry_vaddr; /* 0x401000, 0x101000 (x86_bm), 0x80040 (arm_bm), 0x80000040 (rv_bm) */
        ehdr->e_phoff = 64;
        ehdr->e_shoff = 0;
        ehdr->e_flags = 0;
        ehdr->e_ehsize = sizeof(Elf64Header); /* 64 */
        ehdr->e_phentsize = sizeof(Elf64ProgramHeader); /* 56 */
        ehdr->e_phnum = 1;
        ehdr->e_shentsize = 64;
        ehdr->e_shnum = 0;
        ehdr->e_shstrndx = 0;

        /* 2. ELF64 Program Header (56 bytes) */
        Elf64ProgramHeader *phdr = (Elf64ProgramHeader *)(file_buf + 64);
        phdr->p_type = 1; /* PT_LOAD */
        phdr->p_flags = 5; /* PF_R | PF_X (Strict W^X compliance) */
        phdr->p_offset = 0;
        uint64_t load_vaddr = (target_arch == 3) ? 0x100000 : 
                              (target_arch == 8) ? 0x80000 : 
                              (target_arch == 9) ? 0x80000000 : 0x400000;
        phdr->p_vaddr = load_vaddr;
        phdr->p_paddr = load_vaddr;
        phdr->p_filesz = total_file_size;
        phdr->p_memsz = (target_arch == 0) ? (total_file_size + 0x100000) : total_file_size;
        phdr->p_align = 0x1000;
    }

    /* 3. Universal Hologram Header (96 bytes) */
    UniversalHologramHeader *holo = (UniversalHologramHeader *)(file_buf + holo_offset);
    holo->magic = EIA_MAGIC_HOLO; /* 0x44484945 'EIAH' */
    holo->version_major = EIA_VERSION_MAJOR; /* 2 */
    holo->version_minor = EIA_VERSION_MINOR; /* 0 */
    holo->abi_epoch = 1;
    holo->contracts_offset = contracts_offset;
    holo->contracts_count = unit->contract_count;
    holo->relocs_offset = relocs_offset;
    holo->relocs_count = unit->reloc_count;
    holo->type_graph_offset = type_graph_offset;
    holo->type_graph_size = type_graph_size;
    holo->flags = 1;

    /* 4. Symbol Contracts */
    if (unit->contract_count > 0 && unit->contracts) {
        memcpy(file_buf + contracts_offset, unit->contracts, contracts_size);
    }

    /* 5. EIA Relocation Holes */
    if (unit->reloc_count > 0 && unit->relocs) {
        memcpy(file_buf + relocs_offset, unit->relocs, relocs_size);
    }

    /* 6. EIA Type Graph */
    if (unit->type_graph_count > 0 && unit->type_graph) {
        memcpy(file_buf + type_graph_offset, unit->type_graph, type_graph_size);
    }

    /* Dynamic BLAKE3-64 root hash over contracts, relocs, and type_graph */
    uint64_t tables_len = contracts_size + relocs_size + type_graph_size;
    holo->blake3_root = blake3_hash64(file_buf + contracts_offset, tables_len);

    /* 7. .text Section (starts at file offset 0x1000, mapped to 0x401000) */
    if (unit->text_size > 0 && unit->text_buf) {
        memcpy(file_buf + text_offset, unit->text_buf, unit->text_size);

        /* Pre-resolve internal field holes so standalone binaries execute cleanly out-of-the-box */
        for (uint32_t r = 0; r < unit->reloc_count; ++r) {
            const EiaRelocHole *h = &unit->relocs[r];
            if (h->patch_kind == EIA_PATCH_FIELD_DISP32 && h->insn_offset + 4 <= unit->text_size) {
                for (uint32_t t = 0; t < unit->type_graph_count; ++t) {
                    if (unit->type_graph[t].type_sig_hash == h->type_sig_hash &&
                        unit->type_graph[t].field_hash == h->field_or_sym_hash) {
                        uint32_t disp = unit->type_graph[t].byte_offset;
                        uint8_t *p = file_buf + text_offset + h->insn_offset;
                        if (target_arch == 1) {
                            /* ARM64: movz x16 and movk x16 */
                            uint32_t movz = 0xd2800010 | ((disp & 0xffff) << 5);
                            uint32_t movk = 0xf2a00010 | (((disp >> 16) & 0xffff) << 5);
                            memcpy(p, &movz, 4);
                            memcpy(p + 4, &movk, 4);
                        } else if (target_arch == 2) {
                            /* RISC-V 64: lui t0 and addi t0 */
                            uint32_t hi = (disp + 0x800) >> 12;
                            uint32_t lo = disp & 0xFFF;
                            uint32_t lui = 0x000002b7 | (hi << 12);
                            uint32_t addi = 0x00028293 | (lo << 20);
                            memcpy(p, &lui, 4);
                            memcpy(p + 4, &addi, 4);
                        } else {
                            /* x86-64: 32-bit LE displacement */
                            p[0] = (uint8_t)(disp & 0xFF);
                            p[1] = (uint8_t)((disp >> 8) & 0xFF);
                            p[2] = (uint8_t)((disp >> 16) & 0xFF);
                            p[3] = (uint8_t)((disp >> 24) & 0xFF);
                        }
                        break;
                    }
                }
            }
        }
    }

    /* 8. .rodata Section (starts at file offset 0x3000, mapped to 0x403000) */
    if (unit->rodata_size > 0 && unit->rodata_buf) {
        memcpy(file_buf + rodata_offset, unit->rodata_buf, unit->rodata_size);
    }

    if (out_size) *out_size = total_file_size;
    return file_buf;
}

static uint8_t *spark0_create_pe_buf(const CompiledUnit *unit, size_t *out_size, int is_uefi) {
    uint32_t align = 0x1000; /* 4KB page alignment */
    uint32_t text_aligned = (unit->text_size + align - 1) & ~(align - 1);
    if (text_aligned == 0) text_aligned = align;
    uint32_t rodata_aligned = (unit->rodata_size + align - 1) & ~(align - 1);

    uint32_t headers_size = 0x1000;
    uint32_t text_offset = headers_size;
    uint32_t rodata_offset = text_offset + text_aligned;
    uint32_t total_file_size = rodata_offset + rodata_aligned;

    uint8_t *file_buf = (uint8_t *)calloc(total_file_size, 1);
    if (!file_buf) return NULL;

    /* 1. DOS MZ Header (64 bytes) */
    file_buf[0] = 'M'; file_buf[1] = 'Z';
    file_buf[2] = 0x90; file_buf[3] = 0x00;
    file_buf[4] = 0x03; file_buf[5] = 0x00;
    file_buf[8] = 0x04; file_buf[9] = 0x00;
    file_buf[12] = 0xFF; file_buf[13] = 0xFF;
    file_buf[16] = 0xB8; file_buf[17] = 0x00;
    file_buf[24] = 0x40; file_buf[25] = 0x00;
    /* e_lfanew at offset 0x3C points to 0x80 */
    file_buf[0x3C] = 0x80;

    /* DOS Stub */
    const char dos_msg[] = "This program cannot be run in DOS mode.\r\r\n$";
    memcpy(file_buf + 0x40, dos_msg, sizeof(dos_msg) - 1);

    /* 2. PE Signature at 0x80 */
    uint64_t pe_base = 0x80;
    memcpy(file_buf + pe_base, "PE\0\0", 4);

    /* 3. COFF File Header at 0x84 (20 bytes) */
    uint64_t coff_base = pe_base + 4;
    file_buf[coff_base + 0] = 0x64; file_buf[coff_base + 1] = 0x86; /* Machine = 0x8664 (AMD64) */
    file_buf[coff_base + 2] = 2;    file_buf[coff_base + 3] = 0;    /* NumberOfSections = 2 */
    file_buf[coff_base + 16] = 240; file_buf[coff_base + 17] = 0;   /* SizeOfOptionalHeader = 240 */
    uint16_t pe_char = is_uefi ? 0x202E : 0x0023; /* 0x0023 = RELOCS_STRIPPED | EXECUTABLE | LARGE_ADDRESS_AWARE */
    file_buf[coff_base + 18] = (uint8_t)(pe_char & 0xFF);
    file_buf[coff_base + 19] = (uint8_t)((pe_char >> 8) & 0xFF);

    /* 4. PE32+ Optional Header at 0x98 (240 bytes) */
    uint64_t opt_base = coff_base + 20;
    file_buf[opt_base + 0] = 0x0B; file_buf[opt_base + 1] = 0x02;   /* Magic = 0x020B (PE32+) */
    file_buf[opt_base + 2] = 1;    file_buf[opt_base + 3] = 0;      /* Linker version 1.0 */
    set_u32(file_buf, (opt_base + 4) / 4, text_aligned);            /* SizeOfCode */
    set_u32(file_buf, (opt_base + 8) / 4, rodata_aligned);          /* SizeOfInitializedData */
    set_u32(file_buf, (opt_base + 12) / 4, 0);                      /* SizeOfUninitializedData */
    set_u32(file_buf, (opt_base + 16) / 4, text_offset);            /* AddressOfEntryPoint = 0x1000 */
    set_u32(file_buf, (opt_base + 20) / 4, text_offset);            /* BaseOfCode = 0x1000 */

    if (is_uefi) {
        set_u32(file_buf, (opt_base + 24) / 4, 0x00400000);        /* ImageBase = 0x400000 */
        set_u32(file_buf, (opt_base + 28) / 4, 0x00000000);
    } else {
        set_u32(file_buf, (opt_base + 24) / 4, 0x40000000);        /* ImageBase = 0x140000000 */
        set_u32(file_buf, (opt_base + 28) / 4, 0x00000001);
    }

    set_u32(file_buf, (opt_base + 32) / 4, align);                  /* SectionAlignment = 0x1000 */
    set_u32(file_buf, (opt_base + 36) / 4, align);                  /* FileAlignment = 0x1000 */
    file_buf[opt_base + 40] = 6; file_buf[opt_base + 41] = 0;       /* MajorOperatingSystemVersion = 6 */
    file_buf[opt_base + 48] = 6; file_buf[opt_base + 49] = 0;       /* MajorSubsystemVersion = 6 */
    set_u32(file_buf, (opt_base + 56) / 4, total_file_size);        /* SizeOfImage */
    set_u32(file_buf, (opt_base + 60) / 4, headers_size);           /* SizeOfHeaders = 0x1000 */
    file_buf[opt_base + 68] = is_uefi ? 10 : 3;                     /* Subsystem: 10=EFI, 3=CUI */
    file_buf[opt_base + 69] = 0;
    if (!is_uefi) {
        file_buf[opt_base + 70] = 0x20; file_buf[opt_base + 71] = 0x81; /* DllCharacteristics = 0x8120: NX_COMPAT | TERMINAL_SERVER_AWARE */
    }
    set_u32(file_buf, (opt_base + 72) / 4, 0x200000);               /* SizeOfStackReserve = 2MB */
    set_u32(file_buf, (opt_base + 80) / 4, 0x1000);                 /* SizeOfStackCommit = 4KB */
    set_u32(file_buf, (opt_base + 88) / 4, 0x100000);               /* SizeOfHeapReserve = 1MB */
    set_u32(file_buf, (opt_base + 96) / 4, 0x1000);                 /* SizeOfHeapCommit = 4KB */
    set_u32(file_buf, (opt_base + 108) / 4, 16);                    /* NumberOfRvaAndSizes = 16 */

    /* 5. Section Table at opt_base + 240 = 0x188 */
    uint64_t sec_base = opt_base + 240;

    /* Section 1: .text */
    memcpy(file_buf + sec_base, ".text\0\0\0", 8);
    set_u32(file_buf, (sec_base + 8) / 4, (uint32_t)unit->text_size); /* VirtualSize */
    set_u32(file_buf, (sec_base + 12) / 4, text_offset);             /* VirtualAddress */
    set_u32(file_buf, (sec_base + 16) / 4, text_aligned);            /* SizeOfRawData */
    set_u32(file_buf, (sec_base + 20) / 4, text_offset);             /* PointerToRawData */
    set_u32(file_buf, (sec_base + 36) / 4, 0x60000020);              /* CNT_CODE | MEM_EXECUTE | MEM_READ */

    /* Section 2: .rdata */
    uint64_t rdata_sec = sec_base + 40;
    memcpy(file_buf + rdata_sec, ".rdata\0\0", 8);
    set_u32(file_buf, (rdata_sec + 8) / 4, (uint32_t)unit->rodata_size); /* VirtualSize */
    set_u32(file_buf, (rdata_sec + 12) / 4, rodata_offset);             /* VirtualAddress */
    set_u32(file_buf, (rdata_sec + 16) / 4, rodata_aligned);            /* SizeOfRawData */
    set_u32(file_buf, (rdata_sec + 20) / 4, rodata_offset);             /* PointerToRawData */
    set_u32(file_buf, (rdata_sec + 36) / 4, 0x40000040);              /* CNT_INITIALIZED_DATA | MEM_READ */

    /* Copy payload data */
    if (unit->text_size > 0 && unit->text_buf) {
        memcpy(file_buf + text_offset, unit->text_buf, unit->text_size);
    }
    if (unit->rodata_size > 0 && unit->rodata_buf) {
        memcpy(file_buf + rodata_offset, unit->rodata_buf, unit->rodata_size);
    }

    if (out_size) *out_size = total_file_size;
    return file_buf;
}

static uint8_t *spark0_create_macho_buf(const CompiledUnit *unit, size_t *out_size) {
    uint32_t align = 0x1000;
    uint32_t text_aligned = (unit->text_size + align - 1) & ~(align - 1);
    if (text_aligned == 0) text_aligned = align;
    uint32_t rodata_aligned = (unit->rodata_size + align - 1) & ~(align - 1);

    uint32_t headers_size = 0x1000;
    uint32_t text_offset = headers_size;
    uint32_t rodata_offset = text_offset + text_aligned;
    uint32_t total_file_size = rodata_offset + rodata_aligned;

    uint8_t *file_buf = (uint8_t *)calloc(total_file_size, 1);
    if (!file_buf) return NULL;

    /* Mach-O 64-bit Header (32 bytes) */
    set_u32(file_buf, 0, 0xFEEDFACF); /* MH_MAGIC_64 */
    set_u32(file_buf, 1, 0x01000007); /* CPU_TYPE_X86_64 */
    set_u32(file_buf, 2, 0x80000003); /* CPU_SUBTYPE_LIB64 | CPU_SUBTYPE_X86_64_ALL */
    set_u32(file_buf, 3, 2);          /* MH_EXECUTE */
    set_u32(file_buf, 4, 3);          /* ncmds = 3 */
    set_u32(file_buf, 5, 72 + 152 + 24); /* sizeofcmds = 248 */
    set_u32(file_buf, 6, 0x00200085); /* flags: MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL | MH_PIE */
    set_u32(file_buf, 7, 0);          /* reserved */

    /* Command 1: LC_SEGMENT_64 for __PAGEZERO (72 bytes) at offset 32 */
    uint64_t cmd1 = 32;
    set_u32(file_buf, (cmd1 + 0) / 4, 0x19); /* LC_SEGMENT_64 */
    set_u32(file_buf, (cmd1 + 4) / 4, 72);   /* cmdsize */
    memcpy(file_buf + cmd1 + 8, "__PAGEZERO", 10);
    set_u32(file_buf, (cmd1 + 24) / 4, 0x00000000);
    set_u32(file_buf, (cmd1 + 28) / 4, 0x00000001); /* vmsize = 4GB (0x100000000) */

    /* Command 2: LC_SEGMENT_64 for __TEXT (152 bytes) at offset 104 */
    uint64_t cmd2 = cmd1 + 72;
    set_u32(file_buf, (cmd2 + 0) / 4, 0x19);  /* LC_SEGMENT_64 */
    set_u32(file_buf, (cmd2 + 4) / 4, 152);  /* cmdsize = 72 + 80 */
    memcpy(file_buf + cmd2 + 8, "__TEXT", 6);
    set_u32(file_buf, (cmd2 + 24) / 4, 0x00000000);
    set_u32(file_buf, (cmd2 + 28) / 4, 0x00000001); /* vmaddr = 0x100000000 */
    set_u32(file_buf, (cmd2 + 32) / 4, total_file_size); /* vmsize */
    set_u32(file_buf, (cmd2 + 40) / 4, 0);               /* fileoff */
    set_u32(file_buf, (cmd2 + 48) / 4, total_file_size); /* filesize */
    set_u32(file_buf, (cmd2 + 56) / 4, 7); /* maxprot = VM_PROT_ALL */
    set_u32(file_buf, (cmd2 + 60) / 4, 5); /* initprot = VM_PROT_READ | VM_PROT_EXECUTE */
    set_u32(file_buf, (cmd2 + 64) / 4, 1); /* nsects = 1 */
    set_u32(file_buf, (cmd2 + 68) / 4, 0); /* flags = 0 */

    /* Section 1 inside __TEXT: __text (80 bytes) at cmd2 + 72 */
    uint64_t sect = cmd2 + 72;
    memcpy(file_buf + sect + 0, "__text", 6);
    memcpy(file_buf + sect + 16, "__TEXT", 6);
    set_u32(file_buf, (sect + 32) / 4, text_offset); /* addr = 0x100001000 */
    set_u32(file_buf, (sect + 36) / 4, 0x00000001);
    set_u32(file_buf, (sect + 40) / 4, (uint32_t)unit->text_size); /* size */
    set_u32(file_buf, (sect + 48) / 4, text_offset);               /* offset */
    set_u32(file_buf, (sect + 52) / 4, 4);                         /* align = 2^4 = 16 */
    set_u32(file_buf, (sect + 56) / 4, 0);                         /* reloff */
    set_u32(file_buf, (sect + 60) / 4, 0);                         /* nreloc */
    set_u32(file_buf, (sect + 64) / 4, 0x80000400);                 /* flags: S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS */

    /* Command 3: LC_MAIN (24 bytes) at offset 256 */
    uint64_t cmd3 = cmd2 + 152;
    set_u32(file_buf, (cmd3 + 0) / 4, 0x80000028); /* LC_MAIN */
    set_u32(file_buf, (cmd3 + 4) / 4, 24);         /* cmdsize */
    set_u32(file_buf, (cmd3 + 8) / 4, text_offset); /* entryoff = 0x1000 */
    set_u32(file_buf, (cmd3 + 12) / 4, 0);
    set_u32(file_buf, (cmd3 + 16) / 4, 0);         /* stacksize = 0 (default) */
    set_u32(file_buf, (cmd3 + 20) / 4, 0);

    /* Copy payload */
    if (unit->text_size > 0 && unit->text_buf) {
        memcpy(file_buf + text_offset, unit->text_buf, unit->text_size);
    }
    if (unit->rodata_size > 0 && unit->rodata_buf) {
        memcpy(file_buf + rodata_offset, unit->rodata_buf, unit->rodata_size);
    }

    if (out_size) *out_size = total_file_size;
    return file_buf;
}

int spark0_write_elf_opt(const CompiledUnit *unit, const char *out_path, int is_upbp, int target_arch, int is_signed) {
    size_t total_file_size = 0;
    uint8_t *file_buf = NULL;
    if (target_arch == 4 || target_arch == 6) {
        file_buf = spark0_create_pe_buf(unit, &total_file_size, target_arch == 4);
    } else if (target_arch == 7) {
        file_buf = spark0_create_macho_buf(unit, &total_file_size);
    } else {
        file_buf = spark0_create_elf_buf(unit, &total_file_size, is_upbp, target_arch);
    }
    if (!file_buf) return -1;

    uint64_t holo_offset = is_upbp ? 1152 : 0x80;
    UniversalHologramHeader *holo = (UniversalHologramHeader *)(file_buf + holo_offset);

    if (is_signed && (target_arch != 4 && target_arch != 6 && target_arch != 7)) {
        uint64_t contracts_offset = is_upbp ? 1248 : (holo_offset + sizeof(UniversalHologramHeader));
        uint64_t contracts_size = unit->contract_count * sizeof(SymbolContract);
        uint64_t relocs_offset = contracts_offset + contracts_size;
        uint64_t relocs_size = unit->reloc_count * sizeof(EiaRelocHole);
        uint64_t type_graph_offset = relocs_offset + relocs_size;
        uint64_t type_graph_size = unit->type_graph_count * sizeof(EiaTypeGraphEntry);

        uint64_t auth_offset = type_graph_offset + type_graph_size;
        uint64_t auth_size = sizeof(EiaSignatureRecord);
        EiaSignatureRecord sig_rec;
        memset(&sig_rec, 0, sizeof(sig_rec));
        sig_rec.magic = EIA_AUTH_MAGIC;
        sig_rec.version = EIA_AUTH_VERSION;
        uint16_t signing_epoch = 0;
        sig_rec.public_key_id = eia_get_active_signing_key_id(&signing_epoch, NULL);
        sig_rec.key_epoch = signing_epoch;

        /* Prepare signature slot with zeroed digest and signature in file_buf */
        memcpy(file_buf + auth_offset, &sig_rec, sizeof(sig_rec));
        memcpy(&holo->reserved[0], &auth_offset, 8);
        memcpy(&holo->reserved[8], &auth_size, 8);
        holo->flags |= 2; /* EIA_FLAG_AUTHENTICATED */

        /* Full 256-bit BLAKE3 digest of entire canonical artifact */
        blake3_hash256(file_buf, total_file_size, sig_rec.blake3_digest);
        if (spark0_sign_digest(sig_rec.blake3_digest, sig_rec.key_epoch, sig_rec.signature) != 0) {
            fprintf(stderr, "[EIA ERROR] Failed to sign artifact '%s': external signing key required\n", out_path);
            free(file_buf);
            return -1;
        }

        memcpy(file_buf + auth_offset, &sig_rec, sizeof(sig_rec));
    }

    /* Write to file */
    FILE *f = fopen(out_path, "wb");
    if (!f) {
        perror("fopen output binary");
        free(file_buf);
        return -1;
    }
    size_t written = fwrite(file_buf, 1, total_file_size, f);
    fclose(f);
    free(file_buf);

    if (written != total_file_size) {
        fprintf(stderr, "Failed to write complete binary to '%s'\n", out_path);
        return -1;
    }

    /* Set executable permissions 0755 */
    if (chmod(out_path, 0755) != 0) {
        perror("chmod 0755");
        return -1;
    }

    /* Emit raw binary image alongside ELF for bare-metal targets */
    if (target_arch == 8 || target_arch == 9) {
        char bin_path[512];
        snprintf(bin_path, sizeof(bin_path), "%s.bin", out_path);
        FILE *bf = fopen(bin_path, "wb");
        if (bf) {
            if (unit->text_size > 0 && unit->text_buf) {
                fwrite(unit->text_buf, 1, unit->text_size, bf);
            }
            if (unit->rodata_size > 0 && unit->rodata_buf) {
                fwrite(unit->rodata_buf, 1, unit->rodata_size, bf);
            }
            fclose(bf);
            chmod(bin_path, 0644);
        }
    }

    return 0;
}

int spark0_write_universal_binary(const CompiledUnit *u_x86, const CompiledUnit *u_arm, const CompiledUnit *u_riscv, const char *out_path, int is_signed) {
    size_t sz_x86 = 0, sz_arm = 0, sz_riscv = 0;
    uint8_t *buf_x86 = spark0_create_elf_buf(u_x86, &sz_x86, 0, 0);
    uint8_t *buf_arm = spark0_create_elf_buf(u_arm, &sz_arm, 0, 1);
    uint8_t *buf_riscv = spark0_create_elf_buf(u_riscv, &sz_riscv, 0, 2);

    if (!buf_x86 || !buf_arm || !buf_riscv) {
        if (buf_x86) free(buf_x86);
        if (buf_arm) free(buf_arm);
        if (buf_riscv) free(buf_riscv);
        return -1;
    }

    uint64_t total_size = 0xD0000;
    uint8_t *file_buf = (uint8_t *)calloc(total_size, 1);
    if (!file_buf) {
        free(buf_x86); free(buf_arm); free(buf_riscv);
        return -1;
    }

    /* 1. Versioned EIA Universal Header at Offset 0 (64 bytes) */
    EiaUniversalHeader *uhdr = (EiaUniversalHeader *)file_buf;
    uhdr->magic = EIA_UNIVERSAL_MAGIC; /* 0x41494555 ('UEIA') */
    uhdr->version_major = EIA_UNIVERSAL_VERSION; /* 2 */
    uhdr->version_minor = 0;
    uhdr->flags = 1 | (is_signed ? 2 : 0);
    uhdr->slice_count = 3;
    uhdr->total_size = total_size;

    /* 2. Slice Headers at Offset 64 (3 * 96 = 288 bytes) */
    EiaUniversalSliceHeader *slices = (EiaUniversalSliceHeader *)(file_buf + sizeof(EiaUniversalHeader));

    /* Slice 0: x86_64 */
    slices[0].arch_id = 0;
    slices[0].abi_id = 0; /* SysV */
    slices[0].slice_offset = 0x10000;
    slices[0].slice_size = sz_x86;
    slices[0].text_offset = 0x10000;
    slices[0].text_size = u_x86->text_size;
    slices[0].entry_point = u_x86->entry_vaddr;
    slices[0].holo_offset = 0x10000 + 0x80;
    slices[0].holo_size = sizeof(UniversalHologramHeader);
    blake3_hash256(buf_x86, sz_x86, slices[0].slice_blake3);

    /* Slice 1: arm64 */
    slices[1].arch_id = 1;
    slices[1].abi_id = 3; /* AAPCS */
    slices[1].slice_offset = 0x50000;
    slices[1].slice_size = sz_arm;
    slices[1].text_offset = 0x10000;
    slices[1].text_size = u_arm->text_size;
    slices[1].entry_point = u_arm->entry_vaddr;
    slices[1].holo_offset = 0x50000 + 0x80;
    slices[1].holo_size = sizeof(UniversalHologramHeader);
    blake3_hash256(buf_arm, sz_arm, slices[1].slice_blake3);

    /* Slice 2: riscv64 */
    slices[2].arch_id = 2;
    slices[2].abi_id = 4; /* LP64D */
    slices[2].slice_offset = 0x90000;
    slices[2].slice_size = sz_riscv;
    slices[2].text_offset = 0x10000;
    slices[2].text_size = u_riscv->text_size;
    slices[2].entry_point = u_riscv->entry_vaddr;
    slices[2].holo_offset = 0x90000 + 0x80;
    slices[2].holo_size = sizeof(UniversalHologramHeader);
    blake3_hash256(buf_riscv, sz_riscv, slices[2].slice_blake3);

    uhdr->header_blake3 = blake3_hash64(file_buf, sizeof(EiaUniversalHeader) + 3 * sizeof(EiaUniversalSliceHeader));

    /* 3. Copy individual ISA slices into multi-ISA container */
    memcpy(file_buf + 0x10000, buf_x86, sz_x86);
    memcpy(file_buf + 0x50000, buf_arm, sz_arm);
    memcpy(file_buf + 0x90000, buf_riscv, sz_riscv);

    free(buf_x86);
    free(buf_arm);
    free(buf_riscv);

    /* 4. Cryptographic whole-artifact signing if requested */
    if (is_signed) {
        uint64_t auth_offset = sizeof(EiaUniversalHeader) + 3 * sizeof(EiaUniversalSliceHeader);
        EiaSignatureRecord sig_rec;
        memset(&sig_rec, 0, sizeof(sig_rec));
        sig_rec.magic = EIA_AUTH_MAGIC;
        sig_rec.version = EIA_AUTH_VERSION;
        uint16_t signing_epoch = 0;
        sig_rec.public_key_id = eia_get_active_signing_key_id(&signing_epoch, NULL);
        sig_rec.key_epoch = signing_epoch;

        blake3_hash256(file_buf, total_size, sig_rec.blake3_digest);
        if (spark0_sign_digest(sig_rec.blake3_digest, sig_rec.key_epoch, sig_rec.signature) != 0) {
            fprintf(stderr, "[EIA ERROR] Failed to sign universal artifact '%s'\n", out_path);
            free(file_buf);
            return -1;
        }
        memcpy(file_buf + auth_offset, &sig_rec, sizeof(sig_rec));
    }

    FILE *f = fopen(out_path, "wb");
    if (!f) {
        perror("fopen universal output");
        free(file_buf);
        return -1;
    }
    size_t written = fwrite(file_buf, 1, total_size, f);
    fclose(f);
    free(file_buf);

    if (written != total_size) {
        fprintf(stderr, "Failed to write complete universal binary to '%s'\n", out_path);
        return -1;
    }
    if (chmod(out_path, 0755) != 0) {
        perror("chmod 0755");
        return -1;
    }
    return 0;
}

int spark0_write_elf(const CompiledUnit *unit, const char *out_path, int is_upbp, int target_arch) {
    return spark0_write_elf_opt(unit, out_path, is_upbp, target_arch, 0);
}

int spark0_compile_to_elf_opt(RuModule *module, const char *output_path, int is_upbp, int target_arch, int is_signed) {
    if (target_arch == 5) {
        CompiledUnit *u_x86   = spark0_compile_module(module, 0);
        CompiledUnit *u_arm   = spark0_compile_module(module, 1);
        CompiledUnit *u_riscv = spark0_compile_module(module, 2);
        if (!u_x86 || !u_arm || !u_riscv) {
            if (u_x86) compiled_unit_free(u_x86);
            if (u_arm) compiled_unit_free(u_arm);
            if (u_riscv) compiled_unit_free(u_riscv);
            return -1;
        }
        int rc = spark0_write_universal_binary(u_x86, u_arm, u_riscv, output_path, is_signed);
        compiled_unit_free(u_x86);
        compiled_unit_free(u_arm);
        compiled_unit_free(u_riscv);
        return rc;
    }
    CompiledUnit *u = spark0_compile_module(module, target_arch);
    if (!u) return -1;
    int rc = spark0_write_elf_opt(u, output_path, is_upbp, target_arch, is_signed);
    compiled_unit_free(u);
    return rc;
}

int spark0_compile_to_elf(RuModule *module, const char *output_path, int is_upbp, int target_arch) {
    return spark0_compile_to_elf_opt(module, output_path, is_upbp, target_arch, 0);
}
