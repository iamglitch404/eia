#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <assert.h>
#include "spark0_codegen.h"

int spark0_write_elf(const CompiledUnit *unit, const char *out_path) {
    /* Calculate section offsets */
    uint64_t holo_offset = 0x80;
    uint64_t contracts_offset = holo_offset + sizeof(UniversalHologramHeader); /* 0x80 + 96 = 0xE0 */
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

    /* 3. Universal Hologram Header (96 bytes) at 0x80 */
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
    holo->blake3_root = 0x8877665544332211ULL;
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

int spark0_compile_to_elf(RuModule *module, const char *output_path) {
    CompiledUnit *u = spark0_compile_module(module);
    if (!u) return -1;
    int rc = spark0_write_elf(u, output_path);
    compiled_unit_free(u);
    return rc;
}
