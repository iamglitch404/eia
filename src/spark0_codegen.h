#ifndef SPARK0_CODEGEN_H
#define SPARK0_CODEGEN_H

#include "../include/spark0.h"

typedef struct {
    uint8_t           *text_buf;
    uint32_t           text_size;
    uint32_t           text_cap;

    uint8_t           *rodata_buf;
    uint32_t           rodata_size;
    uint32_t           rodata_cap;

    SymbolContract    *contracts;
    uint32_t           contract_count;
    uint32_t           contract_cap;

    EiaRelocHole      *relocs;
    uint32_t           reloc_count;
    uint32_t           reloc_cap;

    EiaTypeGraphEntry *type_graph;
    uint32_t           type_graph_count;
    uint32_t           type_graph_cap;

    uint64_t           entry_vaddr; /* Virtual address of _start */
    uint64_t           main_vaddr;  /* Virtual address of main */
    uint32_t           start_stub_size;
} CompiledUnit;

CompiledUnit *spark0_compile_module(RuModule *module);
void compiled_unit_free(CompiledUnit *u);

int spark0_write_elf(const CompiledUnit *unit, const char *out_path, int is_upbp);
int spark0_compile_to_elf(RuModule *module, const char *output_path, int is_upbp);

#endif /* SPARK0_CODEGEN_H */
