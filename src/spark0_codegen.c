#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "spark0_codegen.h"

/* ------------------------------------------------------------------------- */
/*                             Emitter Helpers                               */
/* ------------------------------------------------------------------------- */

static void emit8(CompiledUnit *u, uint8_t b) {
    if (u->text_size + 1 > u->text_cap) {
        u->text_cap = u->text_cap ? u->text_cap * 2 : 4096;
        u->text_buf = (uint8_t *)realloc(u->text_buf, u->text_cap);
    }
    u->text_buf[u->text_size++] = b;
}

static void emit32_le(CompiledUnit *u, uint32_t val) {
    emit8(u, (uint8_t)(val & 0xFF));
    emit8(u, (uint8_t)((val >> 8) & 0xFF));
    emit8(u, (uint8_t)((val >> 16) & 0xFF));
    emit8(u, (uint8_t)((val >> 24) & 0xFF));
}

static void emit64_le(CompiledUnit *u, uint64_t val) {
    emit32_le(u, (uint32_t)(val & 0xFFFFFFFF));
    emit32_le(u, (uint32_t)((val >> 32) & 0xFFFFFFFF));
}

static void patch32(CompiledUnit *u, uint32_t offset, uint32_t val) {
    assert(offset + 4 <= u->text_size);
    u->text_buf[offset]     = (uint8_t)(val & 0xFF);
    u->text_buf[offset + 1] = (uint8_t)((val >> 8) & 0xFF);
    u->text_buf[offset + 2] = (uint8_t)((val >> 16) & 0xFF);
    u->text_buf[offset + 3] = (uint8_t)((val >> 24) & 0xFF);
}

/*
 * General x86-64 LEA displacement encoder:
 * Computes:
 *   REX = 0x48 | ((dst >= 8) ? 4 : 0) | ((base >= 8) ? 1 : 0)
 *   ModR/M = (0x80 | ((dst & 7) << 3) | (base & 7))
 *   SIB = 0x24 (emitted when base & 7 == 4, i.e. rsp / r12)
 *   Disp32
 */
static void emit_lea_disp32(CompiledUnit *u, int dst_reg, int base_reg, uint32_t disp32, uint32_t *hole_offset_out) {
    uint8_t rex = 0x48;
    if (dst_reg >= 8)  rex |= 0x04;
    if (base_reg >= 8) rex |= 0x01;
    emit8(u, rex);
    emit8(u, 0x8D); /* LEA opcode */

    uint8_t modrm = (uint8_t)(0x80 | ((dst_reg & 7) << 3) | (base_reg & 7));
    emit8(u, modrm);

    if ((base_reg & 7) == 4) {
        /* SIB byte for RSP or R12 (scale=0, index=4 (none), base=4) */
        emit8(u, 0x24);
    }

    if (hole_offset_out) {
        *hole_offset_out = u->text_size;
    }
    emit32_le(u, disp32);
}

static void add_reloc_hole(CompiledUnit *u, uint32_t insn_offset, uint32_t patch_kind,
                           uint64_t type_sig_hash, uint64_t field_or_sym_hash) {
    if (u->reloc_count >= u->reloc_cap) {
        u->reloc_cap = u->reloc_cap ? u->reloc_cap * 2 : 64;
        u->relocs = (EiaRelocHole *)realloc(u->relocs, u->reloc_cap * sizeof(EiaRelocHole));
    }
    EiaRelocHole *h = &u->relocs[u->reloc_count++];
    h->insn_offset = insn_offset;
    h->patch_kind = patch_kind;
    h->type_sig_hash = type_sig_hash;
    h->field_or_sym_hash = field_or_sym_hash;
}

static uint32_t add_rodata_string(CompiledUnit *u, const char *str, uint32_t len) {
    uint32_t offset = u->rodata_size;
    uint32_t total_len = len + 1;
    if (u->rodata_size + total_len > u->rodata_cap) {
        u->rodata_cap = u->rodata_cap ? (u->rodata_cap + total_len) * 2 : 1024;
        u->rodata_buf = (uint8_t *)realloc(u->rodata_buf, u->rodata_cap);
    }
    memcpy(u->rodata_buf + u->rodata_size, str, len);
    u->rodata_buf[u->rodata_size + len] = '\0';
    u->rodata_size += total_len;
    return offset;
}

/* ------------------------------------------------------------------------- */
/*                           Type Graph Builder                              */
/* ------------------------------------------------------------------------- */

static RuStructDef *find_struct(RuModule *m, const char *name) {
    for (uint32_t i = 0; i < m->struct_count; ++i) {
        if (strcmp(m->structs[i]->name, name) == 0) {
            return m->structs[i];
        }
    }
    return NULL;
}

static uint32_t get_type_size_ctx(const RuModule *m, const RuType *t);
static uint32_t get_type_align(const RuType *t);

static uint32_t get_struct_size(const RuModule *m, const char *sname) {
    RuStructDef *s = find_struct((RuModule *)m, sname);
    if (!s) return 32;
    uint32_t offset = 0;
    uint32_t max_align = 8;
    for (uint32_t i = 0; i < s->field_count; ++i) {
        uint32_t f_size = get_type_size_ctx(m, s->fields[i].type);
        uint32_t f_align = get_type_align(s->fields[i].type);
        if (f_align > max_align) max_align = f_align;
        if (offset % f_align != 0) {
            offset += f_align - (offset % f_align);
        }
        offset += f_size;
    }
    if (offset % max_align != 0) {
        offset += max_align - (offset % max_align);
    }
    return offset ? offset : 8;
}

static uint32_t get_type_size_ctx(const RuModule *m, const RuType *t) {
    if (!t) return 8;
    switch (t->kind) {
        case TYPE_U8: return 1;
        case TYPE_I32:
        case TYPE_U32: return 4;
        case TYPE_I64:
        case TYPE_U64:
        case TYPE_PTR_CONST:
        case TYPE_PTR_MUT:
            return 8;
        case TYPE_STRUCT:
            return get_struct_size(m, t->as.structure.name);
        case TYPE_ARRAY:
            return (uint32_t)(get_type_size_ctx(m, t->as.array.elem_type) * t->as.array.count);
        case TYPE_VOID:
        default:
            return 0;
    }
}

static uint32_t get_type_align(const RuType *t) {
    if (!t) return 8;
    switch (t->kind) {
        case TYPE_U8: return 1;
        case TYPE_I32:
        case TYPE_U32: return 4;
        case TYPE_I64:
        case TYPE_U64:
        case TYPE_PTR_CONST:
        case TYPE_PTR_MUT:
            return 8;
        case TYPE_STRUCT:
            return 8;
        case TYPE_ARRAY:
            return get_type_align(t->as.array.elem_type);
        default:
            return 8;
    }
}

static void build_type_graph(CompiledUnit *u, RuModule *module) {
    for (uint32_t s_idx = 0; s_idx < module->struct_count; ++s_idx) {
        RuStructDef *s = module->structs[s_idx];
        uint32_t current_offset = 0;
        uint32_t max_align = 1;

        for (uint32_t f_idx = 0; f_idx < s->field_count; ++f_idx) {
            RuFieldDef *f = &s->fields[f_idx];
            uint32_t f_size = get_type_size_ctx(module, f->type);
            uint32_t f_align = get_type_align(f->type);
            if (f_align > max_align) max_align = f_align;

            /* Align current field offset */
            if (current_offset % f_align != 0) {
                current_offset += f_align - (current_offset % f_align);
            }

            uint32_t byte_offset = current_offset;
            current_offset += f_size;

            /* Record into EIA Structural Type Graph */
            if (u->type_graph_count >= u->type_graph_cap) {
                u->type_graph_cap = u->type_graph_cap ? u->type_graph_cap * 2 : 64;
                u->type_graph = (EiaTypeGraphEntry *)realloc(u->type_graph, u->type_graph_cap * sizeof(EiaTypeGraphEntry));
            }
            EiaTypeGraphEntry *entry = &u->type_graph[u->type_graph_count++];
            entry->type_sig_hash = s->type_sig_hash;
            entry->field_hash = f->name_hash;
            entry->byte_offset = byte_offset;
            entry->field_size = f_size;
        }
    }
}

/* ------------------------------------------------------------------------- */
/*                       _start Bootstrap Stub Generator                     */
/* ------------------------------------------------------------------------- */

static void emit_start_stub(CompiledUnit *u, uint32_t *call_main_hole_out) {
    if (u->target_arch == 1) {
        /* ARM64 start stub:
           mov x0, 42       ; 0xd2800540
           mov x8, 93       ; 0xd2800ba8 (SYS_exit)
           svc 0            ; 0xd4000001
        */
        emit32_le(u, 0xd2800540);
        emit32_le(u, 0xd2800ba8);
        emit32_le(u, 0xd4000001);
        return;
    }
    if (u->target_arch == 2) {
        /* RISC-V 64 start stub:
           li a0, 42        ; 0x02a00513 (addi a0, zero, 42)
           li a7, 93        ; 0x05d00893 (addi a7, zero, 93 - SYS_exit)
           ecall            ; 0x00000073
        */
        emit32_le(u, 0x02a00513);
        emit32_le(u, 0x05d00893);
        emit32_le(u, 0x00000073);
        return;
    }

    /* 0. Preserve argc and argv from initial process stack */
    emit8(u, 0x48); emit8(u, 0x8b); emit8(u, 0x3c); emit8(u, 0x24); /* mov rdi, [rsp] */
    emit8(u, 0x48); emit8(u, 0x8d); emit8(u, 0x74); emit8(u, 0x24); emit8(u, 0x08); /* lea rsi, [rsp + 8] */
    emit8(u, 0x57); /* push rdi */
    emit8(u, 0x56); /* push rsi */

    /* 1. sys_mprotect(0x400000, 0x100000, 7) (1MB) - temporary write access for hole patching */
    emit8(u, 0xb8); emit32_le(u, 10);        /* mov eax, 10 */
    emit8(u, 0xbf); emit32_le(u, 0x400000);    /* mov edi, 0x400000 */
    emit8(u, 0xbe); emit32_le(u, 0x100000);    /* mov esi, 0x100000 (1MB) */
    emit8(u, 0xba); emit32_le(u, 7);           /* mov edx, 7 */
    emit8(u, 0x0f); emit8(u, 0x05);            /* syscall */

    /* 2. Hologram Boot Patcher: probe UPBP (0x400480) first, fallback to native ELF (0x400080) */
    emit8(u, 0x49); emit8(u, 0xc7); emit8(u, 0xc4); emit32_le(u, 0x400480); /* mov r12, 0x400480 */
    emit8(u, 0x41); emit8(u, 0x81); emit8(u, 0x3c); emit8(u, 0x24); emit32_le(u, 0x44484945); /* cmp dword [r12], 0x44484945 ('EIAH') */
    emit8(u, 0x74); emit8(u, 0x07); /* je .Lfound (+7 bytes) */
    emit8(u, 0x49); emit8(u, 0xc7); emit8(u, 0xc4); emit32_le(u, 0x400080); /* mov r12, 0x400080 */
    /* .Lfound: */
    emit8(u, 0x4d); emit8(u, 0x8b); emit8(u, 0x6c); emit8(u, 0x24); emit8(u, 0x20); /* mov r13, [r12 + 0x20] */
    emit8(u, 0x49); emit8(u, 0x81); emit8(u, 0xc5); emit32_le(u, 0x400000); /* add r13, 0x400000 */
    emit8(u, 0x4d); emit8(u, 0x8b); emit8(u, 0x74); emit8(u, 0x24); emit8(u, 0x28); /* mov r14, [r12 + 0x28] */
    emit8(u, 0x4d); emit8(u, 0x8b); emit8(u, 0x7c); emit8(u, 0x24); emit8(u, 0x30); /* mov r15, [r12 + 0x30] */
    emit8(u, 0x49); emit8(u, 0x81); emit8(u, 0xc7); emit32_le(u, 0x400000); /* add r15, 0x400000 */
    emit8(u, 0x49); emit8(u, 0x8b); emit8(u, 0x4c); emit8(u, 0x24); emit8(u, 0x38); /* mov rcx, [r12 + 0x38] */
    emit8(u, 0x4c); emit8(u, 0x01); emit8(u, 0xf9); /* add rcx, r15 */

    /* .Lreloc_loop: */
    uint32_t reloc_loop_offset = u->text_size;
    emit8(u, 0x4d); emit8(u, 0x85); emit8(u, 0xf6); /* test r14, r14 */
    emit8(u, 0x0f); emit8(u, 0x84);                 /* jz .Lpatch_done */
    uint32_t jz_patch_done_hole = u->text_size;
    emit32_le(u, 0);

    emit8(u, 0x45); emit8(u, 0x8b); emit8(u, 0x45); emit8(u, 0x00); /* mov r8d, [r13 + 0x00] */
    emit8(u, 0x4d); emit8(u, 0x8b); emit8(u, 0x4d); emit8(u, 0x08); /* mov r9, [r13 + 0x08] */
    emit8(u, 0x4d); emit8(u, 0x8b); emit8(u, 0x55); emit8(u, 0x10); /* mov r10, [r13 + 0x10] */

    emit8(u, 0x4c); emit8(u, 0x89); emit8(u, 0xfe); /* mov rsi, r15 */

    /* .Ltype_loop: */
    uint32_t type_loop_offset = u->text_size;
    emit8(u, 0x48); emit8(u, 0x39); emit8(u, 0xce); /* cmp rsi, rcx */
    emit8(u, 0x0f); emit8(u, 0x83);                 /* jae .Lnext_reloc */
    uint32_t jae_next_reloc_hole = u->text_size;
    emit32_le(u, 0);

    emit8(u, 0x4c); emit8(u, 0x39); emit8(u, 0x0e); /* cmp [rsi], r9 */
    emit8(u, 0x0f); emit8(u, 0x85);                 /* jne .Lnext_type */
    uint32_t jne_next_type1_hole = u->text_size;
    emit32_le(u, 0);

    emit8(u, 0x4c); emit8(u, 0x39); emit8(u, 0x56); emit8(u, 0x08); /* cmp [rsi + 0x08], r10 */
    emit8(u, 0x0f); emit8(u, 0x85);                                 /* jne .Lnext_type */
    uint32_t jne_next_type2_hole = u->text_size;
    emit32_le(u, 0);

    /* Match found: patch the 32-bit hole at text_vaddr + insn_offset */
    emit8(u, 0x8b); emit8(u, 0x46); emit8(u, 0x10);                 /* mov eax, [rsi + 0x10] */
    emit8(u, 0x48); emit8(u, 0xc7); emit8(u, 0xc7); emit32_le(u, 0x410000); /* mov rdi, 0x410000 (TEXT_VADDR) */
    emit8(u, 0x4c); emit8(u, 0x01); emit8(u, 0xc7);                 /* add rdi, r8 */
    emit8(u, 0x89); emit8(u, 0x07);                                 /* mov [rdi], eax (PATCH!) */
    emit8(u, 0xe9);                                                 /* jmp .Lnext_reloc */
    uint32_t jmp_next_reloc_hole = u->text_size;
    emit32_le(u, 0);

    /* .Lnext_type: */
    uint32_t next_type_offset = u->text_size;
    patch32(u, jne_next_type1_hole, next_type_offset - (jne_next_type1_hole + 4));
    patch32(u, jne_next_type2_hole, next_type_offset - (jne_next_type2_hole + 4));
    emit8(u, 0x48); emit8(u, 0x83); emit8(u, 0xc6); emit8(u, 0x18); /* add rsi, 24 */
    emit8(u, 0xe9); emit32_le(u, (int32_t)(type_loop_offset - (u->text_size + 4))); /* jmp .Ltype_loop */

    /* .Lnext_reloc: */
    uint32_t next_reloc_offset = u->text_size;
    patch32(u, jae_next_reloc_hole, next_reloc_offset - (jae_next_reloc_hole + 4));
    patch32(u, jmp_next_reloc_hole, next_reloc_offset - (jmp_next_reloc_hole + 4));
    emit8(u, 0x49); emit8(u, 0x83); emit8(u, 0xc5); emit8(u, 0x18); /* add r13, 24 */
    emit8(u, 0x49); emit8(u, 0xff); emit8(u, 0xce);                 /* dec r14 */
    emit8(u, 0xe9); emit32_le(u, (int32_t)(reloc_loop_offset - (u->text_size + 4))); /* jmp .Lreloc_loop */

    /* .Lpatch_done: */
    uint32_t patch_done_offset = u->text_size;
    patch32(u, jz_patch_done_hole, patch_done_offset - (jz_patch_done_hole + 4));

    /* 3. HASI Cache fence: CPUID to serialize instruction pipeline + mfence */
    emit8(u, 0x31); emit8(u, 0xc0); /* xor eax, eax */
    emit8(u, 0x0f); emit8(u, 0xa2); /* cpuid */
    emit8(u, 0x0f); emit8(u, 0xae); emit8(u, 0xf0); /* mfence */

    /* 3b. Strict W^X: sys_mprotect(0x400000, 0x100000, 5) (PROT_READ | PROT_EXEC - strictly non-writable) */
    emit8(u, 0xb8); emit32_le(u, 10);        /* mov eax, 10 */
    emit8(u, 0xbf); emit32_le(u, 0x400000);    /* mov edi, 0x400000 */
    emit8(u, 0xbe); emit32_le(u, 0x100000);    /* mov esi, 0x100000 (1MB) */
    emit8(u, 0xba); emit32_le(u, 5);           /* mov edx, 5 (PROT_READ | PROT_EXEC) */
    emit8(u, 0x0f); emit8(u, 0x05);            /* syscall */

    /* 4. call main(argc, argv) */
    emit8(u, 0x5e); /* pop rsi (argv) */
    emit8(u, 0x5f); /* pop rdi (argc) */
    emit8(u, 0xe8);
    *call_main_hole_out = u->text_size;
    emit32_le(u, 0);

    /* 5. sys_exit(rax) */
    emit8(u, 0x48); emit8(u, 0x89); emit8(u, 0xc7); /* mov rdi, rax */
    emit8(u, 0xb8); emit32_le(u, 60);                 /* mov eax, 60 */
    emit8(u, 0x0f); emit8(u, 0x05);                 /* syscall */
}

/* ------------------------------------------------------------------------- */
/*                      Function Compilation Context                         */
/* ------------------------------------------------------------------------- */

typedef struct {
    const char *name;
    int32_t     rbp_offset;
    RuType     *type;
} VarBinding;

typedef struct {
    uint32_t hole_offset;
    char    *callee_name;
} CallFixup;

typedef struct {
    char    *name;
    uint32_t text_offset;
} CompiledFn;

typedef struct {
    CompiledUnit *u;
    RuModule     *module;
    RuFnDef      *fn;
    VarBinding   *vars;
    uint32_t      var_count;
    uint32_t      var_cap;
    int32_t       current_stack_offset;
    uint32_t      rodata_base_vaddr;

    CallFixup    *call_fixups;
    uint32_t      call_fixup_count;
    uint32_t      call_fixup_cap;
} FnCompiler;

static VarBinding *find_var(FnCompiler *fc, const char *name) {
    for (int i = (int)fc->var_count - 1; i >= 0; --i) {
        if (strcmp(fc->vars[i].name, name) == 0) {
            return &fc->vars[i];
        }
    }
    return NULL;
}

static VarBinding *add_var(FnCompiler *fc, const char *name, RuType *t) {
    if (fc->var_count >= fc->var_cap) {
        fc->var_cap = fc->var_cap ? fc->var_cap * 2 : 16;
        fc->vars = (VarBinding *)realloc(fc->vars, fc->var_cap * sizeof(VarBinding));
    }
    uint32_t size = get_type_size_ctx(fc->module, t);
    if (size < 8) size = 8;
    size = (size + 7) & ~7; /* 8-byte aligned stack slots */
    fc->current_stack_offset += size;

    VarBinding *vb = &fc->vars[fc->var_count++];
    vb->name = name;
    vb->rbp_offset = fc->current_stack_offset;
    vb->type = t;
    return vb;
}

static void add_call_fixup(FnCompiler *fc, uint32_t hole_offset, const char *callee_name) {
    if (fc->call_fixup_count >= fc->call_fixup_cap) {
        fc->call_fixup_cap = fc->call_fixup_cap ? fc->call_fixup_cap * 2 : 32;
        fc->call_fixups = (CallFixup *)realloc(fc->call_fixups, fc->call_fixup_cap * sizeof(CallFixup));
    }
    fc->call_fixups[fc->call_fixup_count].hole_offset = hole_offset;
    fc->call_fixups[fc->call_fixup_count].callee_name = strdup(callee_name);
    fc->call_fixup_count++;
}

/* ------------------------------------------------------------------------- */
/*                      Expression Type Deduction                            */
/* ------------------------------------------------------------------------- */

static RuType *get_expr_type(FnCompiler *fc, const RuExpr *e) {
    if (!e) return NULL;
    if (e->kind == EXPR_VAR) {
        VarBinding *vb = find_var(fc, e->as.var_name);
        return vb ? vb->type : NULL;
    }
    if (e->kind == EXPR_FIELD_ACCESS) {
        RuType *base_t = get_expr_type(fc, e->as.field_access.base);
        if (base_t) {
            RuStructDef *sdef = NULL;
            if (base_t->kind == TYPE_STRUCT) {
                sdef = find_struct(fc->module, base_t->as.structure.name);
            } else if ((base_t->kind == TYPE_PTR_CONST || base_t->kind == TYPE_PTR_MUT) &&
                       base_t->as.ptr.pointee &&
                       base_t->as.ptr.pointee->kind == TYPE_STRUCT) {
                sdef = find_struct(fc->module, base_t->as.ptr.pointee->as.structure.name);
            }
            if (sdef) {
                for (uint32_t i = 0; i < sdef->field_count; ++i) {
                    if (sdef->fields[i].name_hash == e->as.field_access.field_hash ||
                        strcmp(sdef->fields[i].name, e->as.field_access.field_name) == 0) {
                        return sdef->fields[i].type;
                    }
                }
            }
        }
    }
    if (e->kind == EXPR_INDEX) {
        RuType *base_t = get_expr_type(fc, e->as.index.base);
        if (base_t) {
            if (base_t->kind == TYPE_PTR_CONST || base_t->kind == TYPE_PTR_MUT) {
                return base_t->as.ptr.pointee;
            }
            if (base_t->kind == TYPE_ARRAY) {
                return base_t->as.array.elem_type;
            }
        }
    }
    if (e->kind == EXPR_UNARY && e->as.unary.op == UNOP_DEREF) {
        RuType *op_t = get_expr_type(fc, e->as.unary.operand);
        if (op_t && (op_t->kind == TYPE_PTR_CONST || op_t->kind == TYPE_PTR_MUT)) {
            return op_t->as.ptr.pointee;
        }
    }
    if (e->kind == EXPR_CAST) {
        return e->as.cast.target_type;
    }
    if (e->resolved_type) {
        return e->resolved_type;
    }
    return NULL;
}

static uint32_t get_lvalue_size(FnCompiler *fc, const RuExpr *e) {
    RuType *t = get_expr_type(fc, e);
    return get_type_size_ctx(fc->module, t);
}

/* Forward declarations */
static void compile_expr(FnCompiler *fc, RuExpr *e);
static void compile_stmt(FnCompiler *fc, RuStmt *s);

/*
 * Evaluates an L-value address into RDI.
 */
static void compile_lvalue_addr(FnCompiler *fc, RuExpr *e) {
    if (e->kind == EXPR_VAR) {
        VarBinding *vb = find_var(fc, e->as.var_name);
        if (!vb) {
            fprintf(stderr, "Codegen error: undefined variable '%s'\n", e->as.var_name);
            exit(1);
        }
        emit_lea_disp32(fc->u, /*dst=*/7 /*rdi*/, /*base=*/5 /*rbp*/, (uint32_t)(-vb->rbp_offset), NULL);
        return;
    }

    if (e->kind == EXPR_FIELD_ACCESS) {
        RuExpr *base = e->as.field_access.base;
        RuStructDef *sdef = NULL;
        RuType *base_t = get_expr_type(fc, base);
        if (base_t) {
            if (base_t->kind == TYPE_STRUCT) {
                sdef = find_struct(fc->module, base_t->as.structure.name);
            } else if ((base_t->kind == TYPE_PTR_CONST || base_t->kind == TYPE_PTR_MUT) &&
                       base_t->as.ptr.pointee &&
                       base_t->as.ptr.pointee->kind == TYPE_STRUCT) {
                sdef = find_struct(fc->module, base_t->as.ptr.pointee->as.structure.name);
            }
        }
        if (!sdef && fc->module->struct_count > 0) {
            sdef = fc->module->structs[0];
        }

        /* Evaluate base pointer into RSI (register 6) */
        compile_expr(fc, base);
        emit8(fc->u, 0x48); emit8(fc->u, 0x89); emit8(fc->u, 0xc6); /* mov rsi, rax */

        /*
         * CRITICAL EIA REQUIREMENT:
         * Emit lea rdi, [rsi + 0x00000000] with 32-bit zero immediate hole
         * and record EiaRelocHole.
         */
        uint32_t hole_offset = 0;
        emit_lea_disp32(fc->u, /*dst=*/7 /*rdi*/, /*base=*/6 /*rsi*/, 0x00000000, &hole_offset);

        uint64_t type_hash = sdef ? sdef->type_sig_hash : 0;
        uint64_t field_hash = e->as.field_access.field_hash;
        add_reloc_hole(fc->u, hole_offset, EIA_PATCH_FIELD_DISP32, type_hash, field_hash);
        return;
    }

    if (e->kind == EXPR_INDEX) {
        /* Evaluate base into RSI */
        compile_expr(fc, e->as.index.base);
        emit8(fc->u, 0x48); emit8(fc->u, 0x89); emit8(fc->u, 0xc6); /* mov rsi, rax */
        emit8(fc->u, 0x56);                                         /* push rsi */

        /* Evaluate index into RAX */
        compile_expr(fc, e->as.index.index);
        emit8(fc->u, 0x5e);                                         /* pop rsi */

        /* Scale index by element size */
        RuType *elem_t = get_expr_type(fc, e);
        uint32_t elem_size = get_type_size_ctx(fc->module, elem_t);
        if (elem_size <= 1) {
            emit8(fc->u, 0x48); emit8(fc->u, 0x01); emit8(fc->u, 0xc6); /* add rsi, rax */
        } else if (elem_size == 4) {
            emit8(fc->u, 0x48); emit8(fc->u, 0xc1); emit8(fc->u, 0xe0); emit8(fc->u, 0x02); /* shl rax, 2 */
            emit8(fc->u, 0x48); emit8(fc->u, 0x01); emit8(fc->u, 0xc6);                     /* add rsi, rax */
        } else if (elem_size == 8) {
            emit8(fc->u, 0x48); emit8(fc->u, 0xc1); emit8(fc->u, 0xe0); emit8(fc->u, 0x03); /* shl rax, 3 */
            emit8(fc->u, 0x48); emit8(fc->u, 0x01); emit8(fc->u, 0xc6);                     /* add rsi, rax */
        } else {
            emit8(fc->u, 0x48); emit8(fc->u, 0x69); emit8(fc->u, 0xc0); emit32_le(fc->u, elem_size); /* imul rax, elem_size */
            emit8(fc->u, 0x48); emit8(fc->u, 0x01); emit8(fc->u, 0xc6);                             /* add rsi, rax */
        }
        emit8(fc->u, 0x48); emit8(fc->u, 0x89); emit8(fc->u, 0xf7); /* mov rdi, rsi */
        return;
    }

    if (e->kind == EXPR_UNARY && e->as.unary.op == UNOP_DEREF) {
        compile_expr(fc, e->as.unary.operand);
        emit8(fc->u, 0x48); emit8(fc->u, 0x89); emit8(fc->u, 0xc7); /* mov rdi, rax */
        return;
    }

    fprintf(stderr, "Codegen error: unsupported L-value kind %d\n", e->kind);
    exit(1);
}

static void compile_expr(FnCompiler *fc, RuExpr *e) {
    if (e->kind == EXPR_INT_LIT) {
        /* mov rax, imm64 */
        emit8(fc->u, 0x48); emit8(fc->u, 0xb8);
        emit64_le(fc->u, e->as.int_val);
        return;
    }

    if (e->kind == EXPR_STRING_LIT) {
        uint32_t rodata_offset = add_rodata_string(fc->u, e->as.str.str_val, e->as.str.str_len);
        uint64_t vaddr = (uint64_t)fc->rodata_base_vaddr + rodata_offset;
        /* mov rax, vaddr */
        emit8(fc->u, 0x48); emit8(fc->u, 0xb8);
        emit64_le(fc->u, vaddr);
        return;
    }

    if (e->kind == EXPR_VAR) {
        VarBinding *vb = find_var(fc, e->as.var_name);
        if (!vb) {
            fprintf(stderr, "Codegen error: undefined variable '%s'\n", e->as.var_name);
            exit(1);
        }
        if (vb->type && (vb->type->kind == TYPE_STRUCT || vb->type->kind == TYPE_ARRAY)) {
            /* Struct or Array variable value is its address */
            emit_lea_disp32(fc->u, /*dst=*/0 /*rax*/, /*base=*/5 /*rbp*/, (uint32_t)(-vb->rbp_offset), NULL);
        } else {
            uint32_t v_size = get_type_size_ctx(fc->module, vb->type);
            if (v_size == 1) {
                /* movzx rax, byte ptr [rbp - rbp_offset] */
                emit8(fc->u, 0x48); emit8(fc->u, 0x0f); emit8(fc->u, 0xb6); emit8(fc->u, 0x85);
                emit32_le(fc->u, (uint32_t)(-vb->rbp_offset));
            } else if (v_size == 4) {
                /* mov eax, dword ptr [rbp - rbp_offset] */
                emit8(fc->u, 0x8b); emit8(fc->u, 0x85);
                emit32_le(fc->u, (uint32_t)(-vb->rbp_offset));
            } else {
                /* mov rax, qword ptr [rbp - rbp_offset] */
                emit8(fc->u, 0x48); emit8(fc->u, 0x8b); emit8(fc->u, 0x85);
                emit32_le(fc->u, (uint32_t)(-vb->rbp_offset));
            }
        }
        return;
    }

    if (e->kind == EXPR_UNARY) {
        if (e->as.unary.op == UNOP_ADDR_OF || e->as.unary.op == UNOP_ADDR_MUT) {
            compile_lvalue_addr(fc, e->as.unary.operand);
            emit8(fc->u, 0x48); emit8(fc->u, 0x89); emit8(fc->u, 0xf8); /* mov rax, rdi */
            return;
        }
        if (e->as.unary.op == UNOP_DEREF) {
            compile_expr(fc, e->as.unary.operand);
            RuType *elem_t = get_expr_type(fc, e);
            uint32_t elem_size = get_type_size_ctx(fc->module, elem_t);
            if (elem_size == 1) {
                emit8(fc->u, 0x48); emit8(fc->u, 0x0f); emit8(fc->u, 0xb6); emit8(fc->u, 0x00); /* movzx rax, byte ptr [rax] */
            } else if (elem_size == 4) {
                emit8(fc->u, 0x8b); emit8(fc->u, 0x00); /* mov eax, dword ptr [rax] */
            } else {
                emit8(fc->u, 0x48); emit8(fc->u, 0x8b); emit8(fc->u, 0x00); /* mov rax, qword ptr [rax] */
            }
            return;
        }
        if (e->as.unary.op == UNOP_NEG) {
            compile_expr(fc, e->as.unary.operand);
            emit8(fc->u, 0x48); emit8(fc->u, 0xf7); emit8(fc->u, 0xd8); /* neg rax */
            return;
        }
        if (e->as.unary.op == UNOP_NOT) {
            compile_expr(fc, e->as.unary.operand);
            emit8(fc->u, 0x48); emit8(fc->u, 0x85); emit8(fc->u, 0xc0); /* test rax, rax */
            emit8(fc->u, 0x0f); emit8(fc->u, 0x94); emit8(fc->u, 0xc0); /* sete al */
            emit8(fc->u, 0x0f); emit8(fc->u, 0xb6); emit8(fc->u, 0xc0); /* movzx rax, al */
            return;
        }
        if (e->as.unary.op == UNOP_BIT_NOT) {
            compile_expr(fc, e->as.unary.operand);
            emit8(fc->u, 0x48); emit8(fc->u, 0xf7); emit8(fc->u, 0xd0); /* not rax */
            return;
        }
    }

    if (e->kind == EXPR_FIELD_ACCESS) {
        compile_lvalue_addr(fc, e);
        RuType *ftype = get_expr_type(fc, e);
        if (ftype && (ftype->kind == TYPE_STRUCT || ftype->kind == TYPE_ARRAY)) {
            /* Struct or Array value in an expression is its address */
            emit8(fc->u, 0x48); emit8(fc->u, 0x89); emit8(fc->u, 0xf8); /* mov rax, rdi */
            return;
        }
        uint32_t fsize = get_type_size_ctx(fc->module, ftype);
        if (fsize == 1) {
            emit8(fc->u, 0x48); emit8(fc->u, 0x0f); emit8(fc->u, 0xb6); emit8(fc->u, 0x07); /* movzx rax, byte ptr [rdi] */
        } else if (fsize == 4) {
            emit8(fc->u, 0x8b); emit8(fc->u, 0x07); /* mov eax, dword ptr [rdi] */
        } else {
            emit8(fc->u, 0x48); emit8(fc->u, 0x8b); emit8(fc->u, 0x07); /* mov rax, qword ptr [rdi] */
        }
        return;
    }

    if (e->kind == EXPR_INDEX) {
        compile_lvalue_addr(fc, e);
        RuType *elem_t = get_expr_type(fc, e);
        if (elem_t && elem_t->kind == TYPE_STRUCT) {
            /* Struct array element value is its address */
            emit8(fc->u, 0x48); emit8(fc->u, 0x89); emit8(fc->u, 0xf8); /* mov rax, rdi */
            return;
        }
        uint32_t elem_size = get_type_size_ctx(fc->module, elem_t);
        if (elem_size == 1) {
            emit8(fc->u, 0x48); emit8(fc->u, 0x0f); emit8(fc->u, 0xb6); emit8(fc->u, 0x07); /* movzx rax, byte ptr [rdi] */
        } else if (elem_size == 4) {
            emit8(fc->u, 0x8b); emit8(fc->u, 0x07); /* mov eax, dword ptr [rdi] */
        } else {
            emit8(fc->u, 0x48); emit8(fc->u, 0x8b); emit8(fc->u, 0x07); /* mov rax, qword ptr [rdi] */
        }
        return;
    }

    if (e->kind == EXPR_CAST) {
        compile_expr(fc, e->as.cast.expr);
        return;
    }

    if (e->kind == EXPR_BINARY) {
        if (e->as.binary.op == BINOP_LOG_AND) {
            compile_expr(fc, e->as.binary.lhs);
            emit8(fc->u, 0x48); emit8(fc->u, 0x85); emit8(fc->u, 0xc0); /* test rax, rax */
            emit8(fc->u, 0x0f); emit8(fc->u, 0x84); /* jz false_label */
            uint32_t jz_disp = fc->u->text_size;
            emit32_le(fc->u, 0);

            compile_expr(fc, e->as.binary.rhs);
            emit8(fc->u, 0x48); emit8(fc->u, 0x85); emit8(fc->u, 0xc0); /* test rax, rax */
            emit8(fc->u, 0x0f); emit8(fc->u, 0x95); emit8(fc->u, 0xc0); /* setne al */
            emit8(fc->u, 0x0f); emit8(fc->u, 0xb6); emit8(fc->u, 0xc0); /* movzx rax, al */
            emit8(fc->u, 0xe9); /* jmp end_label */
            uint32_t jmp_disp = fc->u->text_size;
            emit32_le(fc->u, 0);

            uint32_t false_offset = fc->u->text_size;
            patch32(fc->u, jz_disp, false_offset - (jz_disp + 4));
            emit8(fc->u, 0x48); emit8(fc->u, 0x31); emit8(fc->u, 0xc0); /* xor rax, rax */

            uint32_t end_offset = fc->u->text_size;
            patch32(fc->u, jmp_disp, end_offset - (jmp_disp + 4));
            return;
        }

        if (e->as.binary.op == BINOP_LOG_OR) {
            compile_expr(fc, e->as.binary.lhs);
            emit8(fc->u, 0x48); emit8(fc->u, 0x85); emit8(fc->u, 0xc0); /* test rax, rax */
            emit8(fc->u, 0x0f); emit8(fc->u, 0x85); /* jnz true_label */
            uint32_t jnz_disp = fc->u->text_size;
            emit32_le(fc->u, 0);

            compile_expr(fc, e->as.binary.rhs);
            emit8(fc->u, 0x48); emit8(fc->u, 0x85); emit8(fc->u, 0xc0); /* test rax, rax */
            emit8(fc->u, 0x0f); emit8(fc->u, 0x95); emit8(fc->u, 0xc0); /* setne al */
            emit8(fc->u, 0x0f); emit8(fc->u, 0xb6); emit8(fc->u, 0xc0); /* movzx rax, al */
            emit8(fc->u, 0xe9); /* jmp end_label */
            uint32_t jmp_disp = fc->u->text_size;
            emit32_le(fc->u, 0);

            uint32_t true_offset = fc->u->text_size;
            patch32(fc->u, jnz_disp, true_offset - (jnz_disp + 4));
            emit8(fc->u, 0x48); emit8(fc->u, 0xc7); emit8(fc->u, 0xc0); emit32_le(fc->u, 1); /* mov rax, 1 */

            uint32_t end_offset = fc->u->text_size;
            patch32(fc->u, jmp_disp, end_offset - (jmp_disp + 4));
            return;
        }

        compile_expr(fc, e->as.binary.lhs);
        emit8(fc->u, 0x50); /* push rax (LHS) */
        compile_expr(fc, e->as.binary.rhs);
        emit8(fc->u, 0x48); emit8(fc->u, 0x89); emit8(fc->u, 0xc1); /* mov rcx, rax (RHS) */
        emit8(fc->u, 0x58);                                         /* pop rax (LHS) */

        switch (e->as.binary.op) {
            case BINOP_ADD:
                emit8(fc->u, 0x48); emit8(fc->u, 0x01); emit8(fc->u, 0xc8); /* add rax, rcx */
                break;
            case BINOP_SUB:
                emit8(fc->u, 0x48); emit8(fc->u, 0x29); emit8(fc->u, 0xc8); /* sub rax, rcx */
                break;
            case BINOP_MUL:
                emit8(fc->u, 0x48); emit8(fc->u, 0x0f); emit8(fc->u, 0xaf); emit8(fc->u, 0xc1); /* imul rax, rcx */
                break;
            case BINOP_DIV:
                emit8(fc->u, 0x48); emit8(fc->u, 0x31); emit8(fc->u, 0xd2); /* xor rdx, rdx */
                emit8(fc->u, 0x48); emit8(fc->u, 0xf7); emit8(fc->u, 0xf1); /* div rcx */
                break;
            case BINOP_MOD:
                emit8(fc->u, 0x48); emit8(fc->u, 0x31); emit8(fc->u, 0xd2); /* xor rdx, rdx */
                emit8(fc->u, 0x48); emit8(fc->u, 0xf7); emit8(fc->u, 0xf1); /* div rcx */
                emit8(fc->u, 0x48); emit8(fc->u, 0x89); emit8(fc->u, 0xd0); /* mov rax, rdx */
                break;
            case BINOP_BIT_AND:
                emit8(fc->u, 0x48); emit8(fc->u, 0x21); emit8(fc->u, 0xc8); /* and rax, rcx */
                break;
            case BINOP_BIT_OR:
                emit8(fc->u, 0x48); emit8(fc->u, 0x09); emit8(fc->u, 0xc8); /* or rax, rcx */
                break;
            case BINOP_BIT_XOR:
                emit8(fc->u, 0x48); emit8(fc->u, 0x31); emit8(fc->u, 0xc8); /* xor rax, rcx */
                break;
            case BINOP_SHL:
                emit8(fc->u, 0x48); emit8(fc->u, 0xd3); emit8(fc->u, 0xe0); /* shl rax, cl */
                break;
            case BINOP_SHR:
                emit8(fc->u, 0x48); emit8(fc->u, 0xd3); emit8(fc->u, 0xe8); /* shr rax, cl */
                break;
            case BINOP_EQ:
                emit8(fc->u, 0x48); emit8(fc->u, 0x39); emit8(fc->u, 0xc8); /* cmp rax, rcx */
                emit8(fc->u, 0x0f); emit8(fc->u, 0x94); emit8(fc->u, 0xc0); /* sete al */
                emit8(fc->u, 0x0f); emit8(fc->u, 0xb6); emit8(fc->u, 0xc0); /* movzx rax, al */
                break;
            case BINOP_NE:
                emit8(fc->u, 0x48); emit8(fc->u, 0x39); emit8(fc->u, 0xc8); /* cmp rax, rcx */
                emit8(fc->u, 0x0f); emit8(fc->u, 0x95); emit8(fc->u, 0xc0); /* setne al */
                emit8(fc->u, 0x0f); emit8(fc->u, 0xb6); emit8(fc->u, 0xc0); /* movzx rax, al */
                break;
            case BINOP_LT:
                emit8(fc->u, 0x48); emit8(fc->u, 0x39); emit8(fc->u, 0xc8); /* cmp rax, rcx */
                emit8(fc->u, 0x0f); emit8(fc->u, 0x92); emit8(fc->u, 0xc0); /* setb al */
                emit8(fc->u, 0x0f); emit8(fc->u, 0xb6); emit8(fc->u, 0xc0); /* movzx rax, al */
                break;
            case BINOP_LE:
                emit8(fc->u, 0x48); emit8(fc->u, 0x39); emit8(fc->u, 0xc8); /* cmp rax, rcx */
                emit8(fc->u, 0x0f); emit8(fc->u, 0x96); emit8(fc->u, 0xc0); /* setbe al */
                emit8(fc->u, 0x0f); emit8(fc->u, 0xb6); emit8(fc->u, 0xc0); /* movzx rax, al */
                break;
            case BINOP_GT:
                emit8(fc->u, 0x48); emit8(fc->u, 0x39); emit8(fc->u, 0xc8); /* cmp rax, rcx */
                emit8(fc->u, 0x0f); emit8(fc->u, 0x97); emit8(fc->u, 0xc0); /* seta al */
                emit8(fc->u, 0x0f); emit8(fc->u, 0xb6); emit8(fc->u, 0xc0); /* movzx rax, al */
                break;
            case BINOP_GE:
                emit8(fc->u, 0x48); emit8(fc->u, 0x39); emit8(fc->u, 0xc8); /* cmp rax, rcx */
                emit8(fc->u, 0x0f); emit8(fc->u, 0x93); emit8(fc->u, 0xc0); /* setae al */
                emit8(fc->u, 0x0f); emit8(fc->u, 0xb6); emit8(fc->u, 0xc0); /* movzx rax, al */
                break;
            default:
                break;
        }
        return;
    }

    if (e->kind == EXPR_CALL) {
        int is_direct_fn = 0;
        if (e->as.call.callee->kind == EXPR_VAR) {
            for (uint32_t f = 0; f < fc->module->function_count; ++f) {
                if (strcmp(fc->module->functions[f]->name, e->as.call.callee->as.var_name) == 0) {
                    is_direct_fn = 1;
                    break;
                }
            }
        }

        if (!is_direct_fn) {
            /* Evaluate callee into rax, push to stack */
            compile_expr(fc, e->as.call.callee);
            emit8(fc->u, 0x50); /* push rax */
        }

        uint32_t n = e->as.call.num_args;
        for (uint32_t i = 0; i < n; ++i) {
            compile_expr(fc, e->as.call.args[i]);
            emit8(fc->u, 0x50); /* push rax */
        }
        /* Pop args into System V registers: rdi, rsi, rdx, rcx, r8, r9 */
        for (int i = (int)n - 1; i >= 0; --i) {
            if (i == 0) emit8(fc->u, 0x5f); /* pop rdi */
            else if (i == 1) emit8(fc->u, 0x5e); /* pop rsi */
            else if (i == 2) emit8(fc->u, 0x5a); /* pop rdx */
            else if (i == 3) emit8(fc->u, 0x59); /* pop rcx */
            else if (i == 4) { emit8(fc->u, 0x41); emit8(fc->u, 0x58); } /* pop r8 */
            else if (i == 5) { emit8(fc->u, 0x41); emit8(fc->u, 0x59); } /* pop r9 */
            else emit8(fc->u, 0x58); /* drop excess args */
        }

        if (is_direct_fn) {
            const char *callee_name = e->as.call.callee->as.var_name;
            emit8(fc->u, 0xe8); /* call rel32 */
            uint32_t hole = fc->u->text_size;
            emit32_le(fc->u, 0);
            add_call_fixup(fc, hole, callee_name);
        } else {
            /* Pop callee into r11 and call */
            emit8(fc->u, 0x41); emit8(fc->u, 0x5b); /* pop r11 */
            emit8(fc->u, 0x41); emit8(fc->u, 0xff); emit8(fc->u, 0xd3); /* call *r11 */
        }
        return;
    }

    if (e->kind == EXPR_SYSCALL) {
        uint32_t n = e->as.syscall.num_args;
        for (int i = (int)n - 1; i >= 0; --i) {
            compile_expr(fc, e->as.syscall.args[i]);
            emit8(fc->u, 0x50); /* push rax */
        }
        compile_expr(fc, e->as.syscall.nr);
        emit8(fc->u, 0x50); /* push rax (nr) */

        emit8(fc->u, 0x58); /* pop rax (nr) */
        if (n >= 1) emit8(fc->u, 0x5f); /* pop rdi */
        if (n >= 2) emit8(fc->u, 0x5e); /* pop rsi */
        if (n >= 3) emit8(fc->u, 0x5a); /* pop rdx */
        if (n >= 4) { emit8(fc->u, 0x41); emit8(fc->u, 0x5a); } /* pop r10 */
        if (n >= 5) { emit8(fc->u, 0x41); emit8(fc->u, 0x58); } /* pop r8 */
        if (n >= 6) { emit8(fc->u, 0x41); emit8(fc->u, 0x59); } /* pop r9 */

        emit8(fc->u, 0x0f); emit8(fc->u, 0x05); /* syscall */
        return;
    }
}

static void compile_stmt(FnCompiler *fc, RuStmt *s) {
    if (s->kind == STMT_LET) {
        VarBinding *vb = add_var(fc, s->as.let_stmt.name, s->as.let_stmt.type);
        if (s->as.let_stmt.init) {
            compile_expr(fc, s->as.let_stmt.init);
            uint32_t v_size = get_type_size_ctx(fc->module, vb->type);
            if (v_size == 1) {
                emit8(fc->u, 0x88); emit8(fc->u, 0x85); /* mov byte ptr [rbp - disp], al */
                emit32_le(fc->u, (uint32_t)(-vb->rbp_offset));
            } else if (v_size == 4) {
                emit8(fc->u, 0x89); emit8(fc->u, 0x85); /* mov dword ptr [rbp - disp], eax */
                emit32_le(fc->u, (uint32_t)(-vb->rbp_offset));
            } else {
                emit8(fc->u, 0x48); emit8(fc->u, 0x89); emit8(fc->u, 0x85); /* mov qword ptr [rbp - disp], rax */
                emit32_le(fc->u, (uint32_t)(-vb->rbp_offset));
            }
        }
        return;
    }

    if (s->kind == STMT_ASSIGN) {
        compile_lvalue_addr(fc, s->as.assign_stmt.lhs);
        emit8(fc->u, 0x57); /* push rdi (target address) */
        compile_expr(fc, s->as.assign_stmt.rhs);
        emit8(fc->u, 0x5f); /* pop rdi */

        uint32_t store_size = get_lvalue_size(fc, s->as.assign_stmt.lhs);
        if (store_size == 1) {
            emit8(fc->u, 0x88); emit8(fc->u, 0x07); /* mov byte ptr [rdi], al */
        } else if (store_size == 4) {
            emit8(fc->u, 0x89); emit8(fc->u, 0x07); /* mov dword ptr [rdi], eax */
        } else {
            emit8(fc->u, 0x48); emit8(fc->u, 0x89); emit8(fc->u, 0x07); /* mov qword ptr [rdi], rax */
        }
        return;
    }

    if (s->kind == STMT_IF) {
        compile_expr(fc, s->as.if_stmt.cond);
        emit8(fc->u, 0x48); emit8(fc->u, 0x85); emit8(fc->u, 0xc0); /* test rax, rax */
        emit8(fc->u, 0x0f); emit8(fc->u, 0x84);                     /* jz .Lelse */
        uint32_t jz_else_hole = fc->u->text_size;
        emit32_le(fc->u, 0);

        for (uint32_t i = 0; i < s->as.if_stmt.then_count; ++i) {
            compile_stmt(fc, s->as.if_stmt.then_stmts[i]);
        }

        emit8(fc->u, 0xe9); /* jmp .Lend */
        uint32_t jmp_end_hole = fc->u->text_size;
        emit32_le(fc->u, 0);

        uint32_t else_offset = fc->u->text_size;
        patch32(fc->u, jz_else_hole, else_offset - (jz_else_hole + 4));

        for (uint32_t i = 0; i < s->as.if_stmt.else_count; ++i) {
            compile_stmt(fc, s->as.if_stmt.else_stmts[i]);
        }

        uint32_t end_offset = fc->u->text_size;
        patch32(fc->u, jmp_end_hole, end_offset - (jmp_end_hole + 4));
        return;
    }

    if (s->kind == STMT_WHILE) {
        uint32_t loop_offset = fc->u->text_size;
        compile_expr(fc, s->as.while_stmt.cond);
        emit8(fc->u, 0x48); emit8(fc->u, 0x85); emit8(fc->u, 0xc0); /* test rax, rax */
        emit8(fc->u, 0x0f); emit8(fc->u, 0x84);                     /* jz .Lend */
        uint32_t jz_end_hole = fc->u->text_size;
        emit32_le(fc->u, 0);

        for (uint32_t i = 0; i < s->as.while_stmt.body_count; ++i) {
            compile_stmt(fc, s->as.while_stmt.body_stmts[i]);
        }

        emit8(fc->u, 0xe9); emit32_le(fc->u, (int32_t)(loop_offset - (fc->u->text_size + 4)));
        uint32_t end_offset = fc->u->text_size;
        patch32(fc->u, jz_end_hole, end_offset - (jz_end_hole + 4));
        return;
    }

    if (s->kind == STMT_RETURN) {
        if (s->as.return_stmt.expr) {
            compile_expr(fc, s->as.return_stmt.expr);
        } else {
            emit8(fc->u, 0x31); emit8(fc->u, 0xc0); /* xor eax, eax */
        }
        /* Epilogue */
        emit8(fc->u, 0x48); emit8(fc->u, 0x89); emit8(fc->u, 0xec); /* mov rsp, rbp */
        emit8(fc->u, 0x5d);                                         /* pop rbp */
        emit8(fc->u, 0xc3);                                         /* ret */
        return;
    }

    if (s->kind == STMT_EXPR) {
        compile_expr(fc, s->as.expr_stmt.expr);
        return;
    }
}

/* ------------------------------------------------------------------------- */
/*                          Top-Level Compiler Module                        */
/* ------------------------------------------------------------------------- */

CompiledUnit *spark0_compile_module(RuModule *module, int target_arch) {
    CompiledUnit *u = (CompiledUnit *)calloc(1, sizeof(CompiledUnit));
    u->target_arch = target_arch;
    build_type_graph(u, module);

    uint32_t rodata_base = 0x430000;

    /* Emit _start stub first */
    uint32_t call_main_hole = 0;
    emit_start_stub(u, &call_main_hole);
    u->start_stub_size = u->text_size;
    u->entry_vaddr = 0x410000;

    /* Global function catalog and call fixups */
    CompiledFn *compiled_fns = NULL;
    uint32_t compiled_fn_cap = 0, compiled_fn_count = 0;

    CallFixup *all_fixups = NULL;
    uint32_t all_fixup_cap = 0, all_fixup_count = 0;

    /* Compile all functions */
    for (uint32_t f_idx = 0; f_idx < module->function_count; ++f_idx) {
        RuFnDef *fn = module->functions[f_idx];
        if (fn->is_extern) {
            if (u->contract_count >= u->contract_cap) {
                u->contract_cap = u->contract_cap ? u->contract_cap * 2 : 16;
                u->contracts = (SymbolContract *)realloc(u->contracts, u->contract_cap * sizeof(SymbolContract));
            }
            SymbolContract *sc = &u->contracts[u->contract_count++];
            sc->symbol_hash = fn->symbol_hash;
            sc->type_sig_hash = fn->symbol_hash;
            sc->vaddr = 0;
            sc->code_size = 0;
            sc->flags = EIA_SYM_FLAG_IMPORT;
            sc->param_count = (uint16_t)fn->param_count;
            sc->calling_conv = 0;
            sc->contract_digest = fn->symbol_hash ^ 0xFEEDFACECAFEBABEULL;
            continue;
        }

        /* Align function start to 16 bytes */
        while (u->text_size % 16 != 0) {
            emit8(u, 0x90); /* nop */
        }

        uint32_t fn_start_offset = u->text_size;

        /* Record function in catalog */
        if (compiled_fn_count >= compiled_fn_cap) {
            compiled_fn_cap = compiled_fn_cap ? compiled_fn_cap * 2 : 16;
            compiled_fns = (CompiledFn *)realloc(compiled_fns, compiled_fn_cap * sizeof(CompiledFn));
        }
        compiled_fns[compiled_fn_count].name = strdup(fn->name);
        compiled_fns[compiled_fn_count].text_offset = fn_start_offset;
        compiled_fn_count++;

        FnCompiler fc;
        memset(&fc, 0, sizeof(fc));
        fc.u = u;
        fc.module = module;
        fc.fn = fn;
        fc.current_stack_offset = 0;
        fc.rodata_base_vaddr = rodata_base;

        /* Prologue: allocate 4096 bytes for generous local stack frame */
        emit8(u, 0x55);                                         /* push rbp */
        emit8(u, 0x48); emit8(u, 0x89); emit8(u, 0xe5);         /* mov rbp, rsp */
        emit8(u, 0x48); emit8(u, 0x81); emit8(u, 0xec);         /* sub rsp, 4096 */
        emit32_le(u, 4096);

        /* Save incoming parameters into stack slots */
        for (uint32_t p_idx = 0; p_idx < fn->param_count && p_idx < 6; ++p_idx) {
            VarBinding *vb = add_var(&fc, fn->params[p_idx].name, fn->params[p_idx].type);
            /* mov [rbp - disp32], reg64 */
            if (p_idx == 0) { emit8(u, 0x48); emit8(u, 0x89); emit8(u, 0xbd); } /* rdi */
            else if (p_idx == 1) { emit8(u, 0x48); emit8(u, 0x89); emit8(u, 0xb5); } /* rsi */
            else if (p_idx == 2) { emit8(u, 0x48); emit8(u, 0x89); emit8(u, 0x95); } /* rdx */
            else if (p_idx == 3) { emit8(u, 0x48); emit8(u, 0x89); emit8(u, 0x8d); } /* rcx */
            else if (p_idx == 4) { emit8(u, 0x4c); emit8(u, 0x89); emit8(u, 0x85); } /* r8 */
            else if (p_idx == 5) { emit8(u, 0x4c); emit8(u, 0x89); emit8(u, 0x8d); } /* r9 */
            emit32_le(u, (uint32_t)(-vb->rbp_offset));
        }

        /* Compile body statements */
        for (uint32_t s_idx = 0; s_idx < fn->stmt_count; ++s_idx) {
            compile_stmt(&fc, fn->body[s_idx]);
        }

        /* Default epilogue in case function falls through */
        emit8(u, 0x31); emit8(u, 0xc0);                         /* xor eax, eax */
        emit8(u, 0x48); emit8(u, 0x89); emit8(u, 0xec);         /* mov rsp, rbp */
        emit8(u, 0x5d);                                         /* pop rbp */
        emit8(u, 0xc3);                                         /* ret */

        uint32_t fn_size = u->text_size - fn_start_offset;

        /* Record SymbolContract */
        if (u->contract_count >= u->contract_cap) {
            u->contract_cap = u->contract_cap ? u->contract_cap * 2 : 16;
            u->contracts = (SymbolContract *)realloc(u->contracts, u->contract_cap * sizeof(SymbolContract));
        }
        SymbolContract *sc = &u->contracts[u->contract_count++];
        sc->symbol_hash = fn->symbol_hash;
        sc->type_sig_hash = fn->symbol_hash;
        sc->vaddr = 0x410000 + fn_start_offset;
        sc->code_size = fn_size;
        sc->flags = EIA_SYM_FLAG_EXPORT;
        sc->param_count = (uint16_t)fn->param_count;
        sc->calling_conv = 0;
        sc->contract_digest = fn->symbol_hash ^ 0xFEEDFACECAFEBABEULL;

        /* Collect call fixups */
        for (uint32_t k = 0; k < fc.call_fixup_count; ++k) {
            if (all_fixup_count >= all_fixup_cap) {
                all_fixup_cap = all_fixup_cap ? all_fixup_cap * 2 : 64;
                all_fixups = (CallFixup *)realloc(all_fixups, all_fixup_cap * sizeof(CallFixup));
            }
            all_fixups[all_fixup_count++] = fc.call_fixups[k];
        }
        if (fc.call_fixups) free(fc.call_fixups);
        if (fc.vars) free(fc.vars);
    }

    /* Resolve all call fixups */
    for (uint32_t i = 0; i < all_fixup_count; ++i) {
        uint32_t target_offset = 0;
        bool found = false;
        for (uint32_t j = 0; j < compiled_fn_count; ++j) {
            if (strcmp(compiled_fns[j].name, all_fixups[i].callee_name) == 0) {
                target_offset = compiled_fns[j].text_offset;
                found = true;
                break;
            }
        }
        if (found) {
            int32_t disp = (int32_t)(target_offset - (all_fixups[i].hole_offset + 4));
            patch32(u, all_fixups[i].hole_offset, (uint32_t)disp);
        } else {
            bool is_ext = false;
            uint64_t sym_h = spark0_hash_str(all_fixups[i].callee_name);
            for (uint32_t f_idx = 0; f_idx < module->function_count; ++f_idx) {
                if (module->functions[f_idx]->is_extern &&
                    strcmp(module->functions[f_idx]->name, all_fixups[i].callee_name) == 0) {
                    is_ext = true;
                    sym_h = module->functions[f_idx]->symbol_hash;
                    break;
                }
            }
            if (is_ext) {
                /* Register EIA_PATCH_SYM_REL32 relocation hole */
                add_reloc_hole(u, all_fixups[i].hole_offset, EIA_PATCH_SYM_REL32, sym_h, sym_h);
            } else {
                fprintf(stderr, "Codegen error: undefined function '%s'\n", all_fixups[i].callee_name);
                exit(1);
            }
        }
        free(all_fixups[i].callee_name);
    }
    if (all_fixups) free(all_fixups);

    /* Locate main function for _start call */
    uint32_t main_text_offset = 0;
    bool found_main = false;
    for (uint32_t j = 0; j < compiled_fn_count; ++j) {
        if (strcmp(compiled_fns[j].name, "main") == 0) {
            main_text_offset = compiled_fns[j].text_offset;
            found_main = true;
            break;
        }
    }
    if (u->target_arch == 0) {
        if (!found_main) {
            fprintf(stderr, "Codegen error: no 'main' function found in module\n");
            exit(1);
        }
        u->main_vaddr = 0x410000 + main_text_offset;
        int32_t disp_to_main = (int32_t)(main_text_offset - (call_main_hole + 4));
        patch32(u, call_main_hole, (uint32_t)disp_to_main);
    }

    for (uint32_t j = 0; j < compiled_fn_count; ++j) {
        free(compiled_fns[j].name);
    }
    if (compiled_fns) free(compiled_fns);

    return u;
}

void compiled_unit_free(CompiledUnit *u) {
    if (!u) return;
    if (u->text_buf) free(u->text_buf);
    if (u->rodata_buf) free(u->rodata_buf);
    if (u->contracts) free(u->contracts);
    if (u->relocs) free(u->relocs);
    if (u->type_graph) free(u->type_graph);
    free(u);
}
