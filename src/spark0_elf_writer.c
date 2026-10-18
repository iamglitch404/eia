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

static uint64_t blake3_compress_64(uint8_t *cv, const uint8_t *block_buf, uint32_t block_len, uint64_t block_index, uint32_t flags) {
    uint8_t state[64];
    for (size_t i = 0; i < 8; ++i) {
        set_u32(state, i, get_u32(cv, i));
    }
    set_u32(state, 8,  1779033703);
    set_u32(state, 9,  3144134277);
    set_u32(state, 10, 1013904242);
    set_u32(state, 11, 2773480762);
    set_u32(state, 12, (uint32_t)(block_index & 0xFFFFFFFF));
    set_u32(state, 13, (uint32_t)(block_index >> 32));
    set_u32(state, 14, block_len);
    set_u32(state, 15, flags);

    uint8_t msg[64];
    memset(msg, 0, 64);
    if (block_len > 0) {
        memcpy(msg, block_buf, block_len > 64 ? 64 : block_len);
    }

    for (size_t round = 0; round < 7; ++round) {
        for (size_t step = 0; step < 8; ++step) {
            blake3_round_g(state, msg, step);
        }
        if (round < 6) {
            blake3_permute_msg(msg);
        }
    }

    for (size_t i = 0; i < 8; ++i) {
        uint32_t new_cv_word = get_u32(state, i) ^ get_u32(state, i + 8);
        set_u32(cv, i, new_cv_word);
    }

    uint64_t low = (uint64_t)get_u32(cv, 0);
    uint64_t high = (uint64_t)get_u32(cv, 1);
    return low | (high << 32);
}

static uint64_t blake3_hash64(const uint8_t *buf, size_t len) {
    uint8_t cv[32];
    set_u32(cv, 0, 1779033703);
    set_u32(cv, 1, 3144134277);
    set_u32(cv, 2, 1013904242);
    set_u32(cv, 3, 2773480762);
    set_u32(cv, 4, 1359893119);
    set_u32(cv, 5, 2600822924);
    set_u32(cv, 6, 528734635);
    set_u32(cv, 7, 1541459225);

    if (len == 0) {
        return blake3_compress_64(cv, buf, 0, 0, 11);
    }

    size_t offset = 0;
    uint64_t block_idx = 0;
    uint64_t digest = 0;

    while (offset < len) {
        uint32_t blk_len = (len - offset > 64) ? 64 : (uint32_t)(len - offset);
        uint32_t flags = 0;
        if (offset == 0) flags |= 1;
        if (offset + blk_len == len) flags |= 2 | 8;

        digest = blake3_compress_64(cv, buf + offset, blk_len, block_idx, flags);
        offset += blk_len;
        block_idx++;
    }

    return digest;
}

int spark0_write_elf(const CompiledUnit *unit, const char *out_path, int is_upbp) {
    /* Calculate section offsets */
    uint64_t holo_offset = is_upbp ? 1152 : 0x80;
    uint64_t contracts_offset = is_upbp ? 1248 : (holo_offset + sizeof(UniversalHologramHeader)); /* 0x80 + 96 = 0xE0 */
    uint64_t contracts_size = unit->contract_count * sizeof(SymbolContract);

    uint64_t relocs_offset = contracts_offset + contracts_size;
    uint64_t relocs_size = unit->reloc_count * sizeof(EiaRelocHole);

    uint64_t type_graph_offset = relocs_offset + relocs_size;
    uint64_t type_graph_size = unit->type_graph_count * sizeof(EiaTypeGraphEntry);

    uint64_t text_offset = 0x10000; /* 64KB into file / 0x410000 vaddr */
    uint64_t rodata_offset = 0x30000; /* 192KB into file / 0x430000 vaddr */
    if (text_offset + unit->text_size > rodata_offset) {
        rodata_offset = (text_offset + unit->text_size + 0xFFF) & ~0xFFFULL;
    }

    uint64_t total_file_size = rodata_offset + ((unit->rodata_size + 0xFFF) & ~0xFFFULL);
    if (total_file_size < rodata_offset + 0x1000) total_file_size = rodata_offset + 0x1000;

    uint8_t *file_buf = (uint8_t *)calloc(total_file_size, 1);
    if (!file_buf) {
        fprintf(stderr, "Failed to allocate %lu bytes for ELF output\n", (unsigned long)total_file_size);
        return -1;
    }

    if (is_upbp) {
        /* 1. POSIX Shell Script Shebang (byte 0-9) */
        memcpy(file_buf, "#!/bin/sh\n", 10);
        /* bytes 10-49: shell trampoline with exit 42 */
        const char *tramp1 = " tail -c+129 \"$0\">z;chmod +x z;exit 42 \n";
        memcpy(file_buf + 10, tramp1, strlen(tramp1));
        /* bytes 50-59: spaces */
        memset(file_buf + 50, ' ', 10);
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
        memcpy(file_buf + 115, "exec /bin/sh -c 'exit 42'\n", 26);

        /* 3. ELF64 Header at elf_base = 128 (0x80) */
        uint64_t elf_base = 128;
        Elf64Header *ehdr = (Elf64Header *)(file_buf + elf_base);
        memcpy(ehdr->e_ident, "\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0", 16);
        ehdr->e_type = 2; /* ET_EXEC */
        ehdr->e_machine = 0x3E; /* EM_X86_64 */
        ehdr->e_version = 1;
        ehdr->e_entry = 0x410000;
        ehdr->e_phoff = 64;
        ehdr->e_ehsize = sizeof(Elf64Header);
        ehdr->e_phentsize = sizeof(Elf64ProgramHeader);
        ehdr->e_phnum = 1;
        ehdr->e_shentsize = 64;

        Elf64ProgramHeader *phdr = (Elf64ProgramHeader *)(file_buf + elf_base + 64);
        phdr->p_type = 1; /* PT_LOAD */
        phdr->p_flags = 7; /* PF_R | PF_W | PF_X */
        phdr->p_offset = 0;
        phdr->p_vaddr = 0x400000;
        phdr->p_paddr = 0x400000;
        phdr->p_filesz = total_file_size;
        phdr->p_memsz = total_file_size + 0x100000;
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
        file_buf[opt_base + 32] = 0; file_buf[opt_base + 33] = 0x10;
        file_buf[opt_base + 36] = 0; file_buf[opt_base + 37] = 0x02;
        file_buf[opt_base + 68] = 3; file_buf[opt_base + 69] = 0;

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
        ehdr->e_machine = 0x3E; /* EM_X86_64 */
        ehdr->e_version = 1;
        ehdr->e_entry = unit->entry_vaddr; /* 0x401000 (_start) */
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
        phdr->p_flags = 7; /* PF_R | PF_W | PF_X */
        phdr->p_offset = 0;
        phdr->p_vaddr = 0x400000;
        phdr->p_paddr = 0x400000;
        phdr->p_filesz = total_file_size;
        phdr->p_memsz = total_file_size + 0x100000; /* Generous memory segment */
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
    }

    /* 8. .rodata Section (starts at file offset 0x3000, mapped to 0x403000) */
    if (unit->rodata_size > 0 && unit->rodata_buf) {
        memcpy(file_buf + rodata_offset, unit->rodata_buf, unit->rodata_size);
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

    return 0;
}

int spark0_compile_to_elf(RuModule *module, const char *output_path, int is_upbp) {
    CompiledUnit *u = spark0_compile_module(module);
    if (!u) return -1;
    int rc = spark0_write_elf(u, output_path, is_upbp);
    compiled_unit_free(u);
    return rc;
}
