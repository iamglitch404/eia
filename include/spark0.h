#ifndef SPARK0_H
#define SPARK0_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================= */
/*                          1. EIA CONSTANTS & MAGIC                         */
/* ========================================================================= */

#define EIA_MAGIC_HOLO         0x44484945U /* 'EIAH' magic: little-endian tag */
#define EIA_VERSION_MAJOR      2U
#define EIA_VERSION_MINOR      0U

#define ELF_MAGIC0             0x7FU
#define ELF_MAGIC1             'E'
#define ELF_MAGIC2             'L'
#define ELF_MAGIC3             'F'

/* Patch Kinds for EiaRelocHole */
typedef enum {
    EIA_PATCH_NONE             = 0,
    EIA_PATCH_FIELD_DISP32     = 1, /* 32-bit displacement in [reg + disp32] */
    EIA_PATCH_SYM_REL32        = 2, /* 32-bit PC-relative call/jmp offset */
    EIA_PATCH_SYM_ABS64        = 3, /* 64-bit absolute symbol address */
    EIA_PATCH_STRUCT_SIZE32    = 4  /* 32-bit struct allocation size immediate */
} EiaPatchKind;

/* Symbol Contract Flags */
typedef enum {
    EIA_SYM_FLAG_EXPORT        = (1U << 0),
    EIA_SYM_FLAG_IMPORT        = (1U << 1),
    EIA_SYM_FLAG_INLINE        = (1U << 2),
    EIA_SYM_FLAG_PURE          = (1U << 3),
    EIA_SYM_FLAG_MUTATING      = (1U << 4)
} EiaSymbolFlags;

/* ========================================================================= */
/*             2. EXACT BINARY LAYOUTS (ELF64 & EIA HOLOGRAM)                */
/* ========================================================================= */

/*
 * Standard ELF64 Header (64 bytes)
 * Exactly 64 bytes. Offsets: 0x00 .. 0x3F.
 */
typedef struct {
    uint8_t  e_ident[16];   /* 0x00: Magic number & ELF identification */
    uint16_t e_type;        /* 0x10: Object file type (ET_EXEC=2, ET_DYN=3) */
    uint16_t e_machine;     /* 0x12: Architecture (EM_X86_64=0x3E) */
    uint32_t e_version;     /* 0x14: Object file version (EV_CURRENT=1) */
    uint64_t e_entry;       /* 0x18: Virtual entry address */
    uint64_t e_phoff;       /* 0x20: Program header table file offset */
    uint64_t e_shoff;       /* 0x28: Section header table file offset */
    uint32_t e_flags;       /* 0x30: Processor-specific flags */
    uint16_t e_ehsize;      /* 0x34: ELF header size in bytes (64) */
    uint16_t e_phentsize;   /* 0x36: Program header table entry size (56) */
    uint16_t e_phnum;       /* 0x38: Program header table entry count */
    uint16_t e_shentsize;   /* 0x3A: Section header table entry size (64) */
    uint16_t e_shnum;       /* 0x3C: Section header table entry count */
    uint16_t e_shstrndx;    /* 0x3E: Section header string table index */
} __attribute__((packed)) Elf64Header;

_Static_assert(sizeof(Elf64Header) == 64, "Elf64Header must be exactly 64 bytes");

/*
 * Standard ELF64 Program Header (56 bytes)
 * Exactly 56 bytes. Offsets: 0x00 .. 0x37.
 */
typedef struct {
    uint32_t p_type;        /* 0x00: Segment type (PT_LOAD=1, PT_NOTE=4, etc.) */
    uint32_t p_flags;       /* 0x04: Segment flags (PF_X=1, PF_W=2, PF_R=4) */
    uint64_t p_offset;      /* 0x08: Segment file offset */
    uint64_t p_vaddr;       /* 0x10: Segment virtual address */
    uint64_t p_paddr;       /* 0x18: Segment physical address */
    uint64_t p_filesz;      /* 0x20: Segment size in file */
    uint64_t p_memsz;       /* 0x28: Segment size in memory */
    uint64_t p_align;       /* 0x30: Segment alignment */
} __attribute__((packed)) Elf64ProgramHeader;

_Static_assert(sizeof(Elf64ProgramHeader) == 56, "Elf64ProgramHeader must be exactly 56 bytes");

/*
 * Universal Hologram Header (96 bytes)
 * Located at the head of the `.eia_hologram` section.
 * Exactly 96 bytes. Offsets: 0x00 .. 0x5F.
 */
typedef struct {
    uint32_t magic;               /* 0x00: Constant 0x44484945 ('EIAH') */
    uint16_t version_major;       /* 0x04: 2 */
    uint16_t version_minor;       /* 0x06: 0 */
    uint64_t abi_epoch;           /* 0x08: Monotonic ABI epoch identifier */
    uint64_t contracts_offset;    /* 0x10: Byte offset to SymbolContract array */
    uint64_t contracts_count;     /* 0x18: Count of SymbolContract entries */
    uint64_t relocs_offset;       /* 0x20: Byte offset to EiaRelocHole array */
    uint64_t relocs_count;        /* 0x28: Count of EiaRelocHole entries */
    uint64_t type_graph_offset;   /* 0x30: Byte offset to serialized type graph */
    uint64_t type_graph_size;     /* 0x38: Byte size of serialized type graph */
    uint64_t blake3_root;         /* 0x40: BLAKE3-64 root hash of the hologram */
    uint64_t flags;               /* 0x48: Hologram capabilities & features */
    uint8_t  reserved[16];        /* 0x50: Reserved padding for 128-bit alignment */
} __attribute__((packed)) UniversalHologramHeader;

_Static_assert(sizeof(UniversalHologramHeader) == 96, "UniversalHologramHeader must be exactly 96 bytes");

/*
 * Alternate 64-byte payload root representation of UniversalHologramHeader
 * for implementations using full 512-bit BLAKE3 tree roots.
 */
typedef struct {
    uint32_t magic;               /* 0x00: 0x44484945 ('EIAH') */
    uint16_t version_major;       /* 0x04: 2 */
    uint16_t version_minor;       /* 0x06: 0 */
    uint32_t contracts_count;     /* 0x08: Count of SymbolContracts */
    uint32_t relocs_count;        /* 0x0C: Count of EiaRelocHoles */
    uint64_t contracts_offset;    /* 0x10: Offset to SymbolContracts */
    uint64_t relocs_offset;       /* 0x18: Offset to EiaRelocHoles */
    uint8_t  blake3_root_64b[64]; /* 0x20: 64-byte (512-bit) BLAKE3 tree root */
} __attribute__((packed)) UniversalHologramHeaderRaw64;

_Static_assert(sizeof(UniversalHologramHeaderRaw64) == 96, "UniversalHologramHeaderRaw64 must be exactly 96 bytes");

/*
 * Symbol Contract Entry (48 bytes)
 * Stored inside `.eia_contract`.
 * Exactly 48 bytes. Offsets: 0x00 .. 0x2F.
 */
typedef enum {
    EIA_CCONV_SYSV   = 0, /* System V AMD64 (default x86-64, standard AAPCS64, standard LP64D) */
    EIA_CCONV_WIN64  = 1, /* Microsoft x64 (Win64) Calling Convention */
    EIA_CCONV_EIA    = 2, /* EIA Sovereign Canonical Cross-ISA ABI */
    EIA_CCONV_AAPCS  = 3, /* ARM64 AAPCS Explicit */
    EIA_CCONV_RISCV  = 4  /* RISC-V 64 LP64D Explicit */
} EiaCallingConv;

typedef struct {
    uint64_t symbol_hash;         /* 0x00: BLAKE3-64 hash of symbol name string */
    uint64_t type_sig_hash;       /* 0x08: BLAKE3-64 structural type signature hash */
    uint64_t vaddr;               /* 0x10: Target virtual address or section offset */
    uint64_t code_size;           /* 0x18: Size of symbol code/data in bytes */
    uint32_t flags;               /* 0x20: EiaSymbolFlags bitfield */
    uint16_t param_count;         /* 0x24: Number of formal parameters */
    uint16_t calling_conv;        /* 0x26: Calling convention (EiaCallingConv) */
    uint64_t contract_digest;     /* 0x28: BLAKE3-64 contract digest over 0x00..0x27 */
} __attribute__((packed)) SymbolContract;

_Static_assert(sizeof(SymbolContract) == 48, "SymbolContract must be exactly 48 bytes");

/*
 * EIA Relocation Hole Entry (24 bytes)
 * Stored inside `.eia_reloc`.
 * Exactly 24 bytes. Offsets: 0x00 .. 0x17.
 */
typedef struct {
    uint32_t insn_offset;         /* 0x00: Offset of 32-bit immediate hole in section */
    uint32_t patch_kind;          /* 0x04: EiaPatchKind (e.g. EIA_PATCH_FIELD_DISP32) */
    uint64_t type_sig_hash;       /* 0x08: BLAKE3-64 structural type signature hash */
    uint64_t field_or_sym_hash;   /* 0x10: BLAKE3-64 field name or symbol hash */
} __attribute__((packed)) EiaRelocHole;

_Static_assert(sizeof(EiaRelocHole) == 24, "EiaRelocHole must be exactly 24 bytes");

/*
 * EIA Structural Type Graph Entry (24 bytes)
 * Stored inside `.eia_typegraph`.
 * Exactly 24 bytes. Offsets: 0x00 .. 0x17.
 */
typedef struct {
    uint64_t type_sig_hash;       /* 0x00: BLAKE3-64 structural type hash */
    uint64_t field_hash;          /* 0x08: BLAKE3-64 field name hash */
    uint32_t byte_offset;         /* 0x10: Physical byte offset within struct */
    uint32_t field_size;          /* 0x14: Size of field in bytes */
} __attribute__((packed)) EiaTypeGraphEntry;

_Static_assert(sizeof(EiaTypeGraphEntry) == 24, "EiaTypeGraphEntry must be exactly 24 bytes");

/* ========================================================================= */
/*       PRODUCTION GDAM (GENERATION-DRIVEN SCHEMA MIGRATION) RUNTIME        */
/* ========================================================================= */

typedef EiaTypeGraphEntry GdamFieldEntry;

typedef struct GdamGeneration {
    uint64_t epoch;
    const uint8_t *record_buf;
    const GdamFieldEntry *schema;
    uint32_t count;
} GdamGeneration;

#define MAX_LOADED_PROVIDERS 64
#define MAX_GDAM_THREADS 128

typedef struct {
    _Atomic(uint64_t) thread_id;
    _Atomic(uint64_t) entered_epoch;
    _Atomic(bool)     in_critical_section;
} GdamThreadSlot;

typedef struct GdamObjectNode {
    void                  **object_ptr_ref; /* Direct reference to application object pointer */
    uint64_t                type_sig_hash;  /* BLAKE3-64 canonical structural hash */
    size_t                  element_count;  /* 1 for single struct, >1 for array of structs */
    size_t                  element_size;   /* Current byte size */
    struct GdamObjectNode  *next;
} GdamObjectNode;

#ifndef _CONCURRENT_GDAM_STATE_DEFINED
#define _CONCURRENT_GDAM_STATE_DEFINED
#include <stdatomic.h>
typedef struct {
    _Atomic(uint64_t)         active_readers;
    _Atomic(GdamGeneration *) active_generation;
    GdamGeneration           *previous_generation;
    GdamGeneration           *staged_generation;
    uint8_t                  *retired_records[MAX_LOADED_PROVIDERS + 1];
    size_t                    retired_count;
    GdamThreadSlot            threads[MAX_GDAM_THREADS];
    _Atomic(size_t)           thread_count;
    GdamObjectNode           *object_graph;
    _Atomic(int)              object_lock;
} ConcurrentGdamState;
#endif

/* Target architecture definitions */
#define EIA_TARGET_X86_64    0
#define EIA_TARGET_ARM64     1
#define EIA_TARGET_RISCV64   2
#define EIA_TARGET_BAREMETAL 3
#define EIA_TARGET_UEFI      4
#define EIA_TARGET_UNIVERSAL 5
#define EIA_TARGET_PE        6
#define EIA_TARGET_MACHO     7
#define MULTIBOOT_HEADER_MAGIC 0x1BADB002

/* EIA Universal Package ('UEIA') Format */
#define EIA_UNIVERSAL_MAGIC   0x41494555U /* 'UEIA' */
#define EIA_UNIVERSAL_VERSION 2U
#define EIA_MAX_SLICES        8

typedef struct {
    uint32_t arch_id;          /* 0=x86_64, 1=arm64, 2=riscv64 */
    uint32_t abi_id;           /* 0=SysV, 1=Win64, 2=EIA, 3=AAPCS, 4=LP64D */
    uint64_t slice_offset;     /* Offset from start of file */
    uint64_t slice_size;       /* Size of slice in bytes */
    uint64_t text_offset;      /* Offset of .text in slice */
    uint64_t text_size;        /* Size of .text in slice */
    uint64_t entry_point;      /* Virtual entry point */
    uint64_t holo_offset;      /* Architecture-specific Universal Hologram offset */
    uint64_t holo_size;        /* Hologram size */
    uint8_t  slice_blake3[32]; /* 256-bit BLAKE3 digest of slice */
} __attribute__((packed)) EiaUniversalSliceHeader;

_Static_assert(sizeof(EiaUniversalSliceHeader) == 96, "EiaUniversalSliceHeader must be exactly 96 bytes");

typedef struct {
    uint32_t magic;            /* 0x41494555 ('UEIA') */
    uint16_t version_major;    /* 2 */
    uint16_t version_minor;    /* 0 */
    uint32_t flags;            /* Bit 0: Valid, Bit 1: Signed */
    uint32_t slice_count;      /* Number of architecture slices */
    uint64_t total_size;       /* Total container file size */
    uint64_t header_blake3;    /* BLAKE3 hash of header + slice table */
    uint8_t  reserved[32];     /* 128-bit alignment padding */
} __attribute__((packed)) EiaUniversalHeader;

_Static_assert(sizeof(EiaUniversalHeader) == 64, "EiaUniversalHeader must be exactly 64 bytes");

/* GDAM Runtime API */
void gdam_init(ConcurrentGdamState *gdam, GdamGeneration *init_gen);
GdamGeneration *gdam_reader_enter(ConcurrentGdamState *gdam);
void gdam_reader_leave(ConcurrentGdamState *gdam);
uint64_t gdam_atomic_publish(ConcurrentGdamState *gdam, GdamGeneration *new_gen);
int gdam_rollback(ConcurrentGdamState *gdam);
void gdam_retire_record(ConcurrentGdamState *gdam, uint8_t *old_rec);
void gdam_reclaim_retired(ConcurrentGdamState *gdam);
size_t gdam_migrate_record(
    const uint8_t *old_buf, const GdamFieldEntry *old_tg, size_t old_count,
    uint8_t *new_buf, const GdamFieldEntry *new_tg, size_t new_count,
    uint64_t type_hash
);
int eia_gdam_stage_upgrade(ConcurrentGdamState *gdam, GdamGeneration *next_gen);
uint64_t eia_gdam_commit_upgrade(ConcurrentGdamState *gdam, GdamGeneration *new_gen, uint64_t type_hash);
int eia_gdam_rollback_upgrade(ConcurrentGdamState *gdam);

/* Dynamic Thread Registration & Multi-Object Graph Migration */
int eia_gdam_register_thread(ConcurrentGdamState *gdam, uint64_t thread_id);
int eia_gdam_unregister_thread(ConcurrentGdamState *gdam, uint64_t thread_id);
void eia_gdam_thread_enter(ConcurrentGdamState *gdam, uint64_t thread_id);
void eia_gdam_thread_leave(ConcurrentGdamState *gdam, uint64_t thread_id);
int eia_gdam_register_object(ConcurrentGdamState *gdam, void **obj_ref, uint64_t type_hash, size_t element_count, size_t elem_size);
int eia_gdam_unregister_object(ConcurrentGdamState *gdam, void **obj_ref);
int eia_gdam_publish_object_pointer(ConcurrentGdamState *gdam, void **obj_ref, void *new_ptr);
uint64_t eia_gdam_migrate_object_graph(ConcurrentGdamState *gdam, GdamGeneration *new_gen, uint64_t type_hash);


/* ========================================================================= */
/*                          3. SPARK-0 TYPE SYSTEM                           */
/* ========================================================================= */

typedef enum {
    TYPE_VOID,
    TYPE_I64,
    TYPE_U64,
    TYPE_I32,
    TYPE_U32,
    TYPE_I16,
    TYPE_U16,
    TYPE_I8,
    TYPE_U8,
    TYPE_F64,
    TYPE_F32,
    TYPE_BOOL,
    TYPE_PTR_CONST,   /* *T */
    TYPE_PTR_MUT,     /* *mut T */
    TYPE_ARRAY,       /* [T; N] */
    TYPE_STRUCT       /* struct Name */
} RuTypeKind;

typedef struct RuType RuType;

struct RuType {
    RuTypeKind kind;
    uint32_t   size_bytes;
    uint32_t   align_bytes;
    uint64_t   type_sig_hash; /* BLAKE3-64 canonical structural hash */
    union {
        struct {
            RuType *pointee;
        } ptr;
        struct {
            RuType  *elem_type;
            uint64_t count;
        } array;
        struct {
            const char *name;
            uint64_t    struct_name_hash;
            uint32_t    field_count;
            struct RuFieldDef *fields;
        } structure;
    } as;
};

/* ========================================================================= */
/*                   4. SPARK-0 AST DATA STRUCTURES                          */
/* ========================================================================= */

typedef enum {
    TOKEN_EOF = 0,
    TOKEN_STRUCT,
    TOKEN_FN,
    TOKEN_EXTERN,
    TOKEN_LET,
    TOKEN_MUT,
    TOKEN_IF,
    TOKEN_ELSE,
    TOKEN_WHILE,
    TOKEN_RETURN,
    TOKEN_AS,
    TOKEN_SYSCALL,
    TOKEN_ASM,

    /* Literals & Identifiers */
    TOKEN_IDENT,
    TOKEN_INT_LIT,
    TOKEN_CHAR_LIT,
    TOKEN_STRING_LIT,

    /* Primitive Type Keywords */
    TOKEN_TYPE_I64,
    TOKEN_TYPE_U64,
    TOKEN_TYPE_I32,
    TOKEN_TYPE_U32,
    TOKEN_TYPE_U8,
    TOKEN_TYPE_VOID,

    /* Operators & Punctuators */
    TOKEN_PLUS,
    TOKEN_MINUS,
    TOKEN_STAR,
    TOKEN_SLASH,
    TOKEN_PERCENT,
    TOKEN_AMP,
    TOKEN_PIPE,
    TOKEN_CARET,
    TOKEN_SHL,
    TOKEN_SHR,
    TOKEN_EQ,
    TOKEN_EQEQ,
    TOKEN_EXCL,
    TOKEN_NEQ,
    TOKEN_LT,
    TOKEN_LTE,
    TOKEN_GT,
    TOKEN_GTE,
    TOKEN_AMPAMP,
    TOKEN_PIPEPIPE,
    TOKEN_TILDE,
    TOKEN_ARROW,       /* -> */
    TOKEN_DOT,
    TOKEN_COMMA,
    TOKEN_COLON,
    TOKEN_SEMICOLON,
    TOKEN_LPAREN,
    TOKEN_RPAREN,
    TOKEN_LBRACE,
    TOKEN_RBRACE,
    TOKEN_LBRACKET,
    TOKEN_RBRACKET,
    TOKEN_HASH         /* # for compiler attributes */
} RuTokenType;

#ifndef _WIN32
typedef RuTokenType TokenType;
#endif

typedef struct {
    uint32_t line;
    uint32_t col;
} SourcePos;

typedef struct RuFieldDef {
    const char *name;
    uint64_t    name_hash;   /* BLAKE3-64 hash of field name */
    RuType     *type;
    SourcePos   pos;
} RuFieldDef;

typedef struct RuStructDef {
    const char *name;
    uint64_t    name_hash;
    uint64_t    type_sig_hash; /* BLAKE3-64 hash of structural signature */
    uint64_t    layout_hash;   /* BLAKE3-64 hash of physical field layout */
    RuFieldDef *fields;
    uint32_t    field_count;
    SourcePos   pos;
} RuStructDef;

typedef struct RuParam {
    const char *name;
    RuType     *type;
    SourcePos   pos;
} RuParam;

typedef enum {
    EXPR_INT_LIT,
    EXPR_STRING_LIT,
    EXPR_VAR,
    EXPR_BINARY,
    EXPR_UNARY,
    EXPR_FIELD_ACCESS, /* ptr.field */
    EXPR_INDEX,        /* arr[idx] */
    EXPR_CALL,         /* fn(args...) */
    EXPR_CAST,         /* expr as Type */
    EXPR_SYSCALL,      /* syscall(nr, a1..a6) */
    EXPR_INLINE_ASM    /* asm("instruction", ...) */
} RuExprKind;

typedef enum {
    BINOP_ADD, BINOP_SUB, BINOP_MUL, BINOP_DIV, BINOP_MOD,
    BINOP_BIT_AND, BINOP_BIT_OR, BINOP_BIT_XOR, BINOP_SHL, BINOP_SHR,
    BINOP_EQ, BINOP_NE, BINOP_LT, BINOP_LE, BINOP_GT, BINOP_GE,
    BINOP_LOG_AND, BINOP_LOG_OR
} RuBinOp;

typedef enum {
    UNOP_NEG,      /* -x */
    UNOP_NOT,      /* !x */
    UNOP_BIT_NOT,  /* ~x */
    UNOP_DEREF,    /* *p */
    UNOP_ADDR_OF,  /* &x */
    UNOP_ADDR_MUT  /* &mut x */
} RuUnaryOp;

typedef struct RuExpr RuExpr;

struct RuExpr {
    RuExprKind kind;
    RuType    *resolved_type;
    SourcePos  pos;
    union {
        uint64_t int_val;
        struct {
            const char *str_val;
            uint32_t    str_len;
        } str;
        const char *var_name;
        struct {
            RuBinOp  op;
            RuExpr  *lhs;
            RuExpr  *rhs;
        } binary;
        struct {
            RuUnaryOp op;
            RuExpr   *operand;
        } unary;
        struct {
            RuExpr     *base;       /* Pointer expression to struct */
            const char *field_name;
            uint64_t    field_hash; /* BLAKE3-64 hash of field name */
        } field_access;
        struct {
            RuExpr *base;
            RuExpr *index;
        } index;
        struct {
            RuExpr  *callee;
            RuExpr **args;
            uint32_t num_args;
        } call;
        struct {
            RuExpr *expr;
            RuType *target_type;
        } cast;
        struct {
            RuExpr  *nr;
            RuExpr **args;
            uint32_t num_args;
        } syscall;
        struct {
            const char *template_str;
            RuExpr    **operands;
            uint32_t    num_operands;
        } inline_asm;
    } as;
};

typedef enum {
    STMT_LET,
    STMT_ASSIGN,
    STMT_IF,
    STMT_WHILE,
    STMT_RETURN,
    STMT_EXPR
} RuStmtKind;

typedef struct RuStmt RuStmt;

struct RuStmt {
    RuStmtKind kind;
    SourcePos  pos;
    union {
        struct {
            const char *name;
            bool        is_mut;
            RuType     *type;
            RuExpr     *init;
        } let_stmt;
        struct {
            RuExpr *lhs;
            RuExpr *rhs;
        } assign_stmt;
        struct {
            RuExpr   *cond;
            RuStmt  **then_stmts;
            uint32_t  then_count;
            RuStmt  **else_stmts;
            uint32_t  else_count;
        } if_stmt;
        struct {
            RuExpr   *cond;
            RuStmt  **body_stmts;
            uint32_t  body_count;
        } while_stmt;
        struct {
            RuExpr *expr; /* NULL if void return */
        } return_stmt;
        struct {
            RuExpr *expr;
        } expr_stmt;
    } as;
};

typedef struct RuFnDef {
    const char  *name;
    uint64_t     symbol_hash;
    uint64_t     type_sig_hash; /* BLAKE3-64 canonical structural function signature */
    RuParam     *params;
    uint32_t     param_count;
    RuType      *return_type;
    RuStmt     **body;
    uint32_t     stmt_count;
    bool         is_extern;
    uint16_t     calling_conv; /* 0=SysV AMD64, 1=Win64, 2=EIA */
    SourcePos    pos;
} RuFnDef;

typedef struct RuModule {
    RuStructDef **structs;
    uint32_t      struct_count;
    RuFnDef     **functions;
    uint32_t      function_count;
} RuModule;

/* ========================================================================= */
/*                   5. FLAT 3-ADDRESS IR REPRESENTATION                     */
/* ========================================================================= */

typedef uint32_t IrReg;
#define IR_REG_NONE ((IrReg)0xFFFFFFFFU)

typedef enum {
    IR_OP_NONE = 0,
    IR_OP_REG,
    IR_OP_IMM64,
    IR_OP_LABEL,
    IR_OP_SYM_HASH
} IrOperandKind;

typedef struct {
    IrOperandKind kind;
    union {
        IrReg    reg;
        uint64_t imm64;
        uint32_t label_id;
        uint64_t sym_hash;
    } as;
} IrOperand;

typedef enum {
    IR_NOP = 0,
    IR_LABEL,

    /* Data Movement */
    IR_MOV,
    IR_CONST,

    /* Arithmetic & Logic */
    IR_ADD,
    IR_SUB,
    IR_MUL,
    IR_DIV,
    IR_MOD,
    IR_BIT_AND,
    IR_BIT_OR,
    IR_BIT_XOR,
    IR_SHL,
    IR_SHR,
    IR_NEG,
    IR_BIT_NOT,

    /* Comparisons */
    IR_CMP_EQ,
    IR_CMP_NE,
    IR_CMP_LT,
    IR_CMP_LE,
    IR_CMP_GT,
    IR_CMP_GE,

    /* Control Flow */
    IR_JMP,
    IR_JMP_IF,
    IR_JMP_IF_NOT,

    /* Function & Syscall Calls */
    IR_CALL,
    IR_RET,
    IR_SYSCALL,

    /* Memory Operations */
    IR_ALLOCA,
    IR_LOAD,
    IR_STORE,

    /*
     * CRITICAL EIA REQUIREMENT:
     * Never hardcode struct field offsets in the IR.
     * Every ptr.field access lowers to IR_FIELD_ADDR.
     */
    IR_FIELD_ADDR,

    /* Low-level Assembly Intrinsic */
    IR_INLINE_ASM
} IrOpcode;

typedef struct IrInsn IrInsn;

struct IrInsn {
    IrOpcode   opcode;
    IrReg      dst;      /* Destination register (IR_REG_NONE if unused) */
    IrOperand  src1;     /* First operand / base register */
    IrOperand  src2;     /* Second operand */
    
    /* Specific payload for IR_FIELD_ADDR */
    struct {
        uint64_t type_hash;  /* BLAKE3-64 structural type hash of the struct */
        uint64_t field_hash; /* BLAKE3-64 hash of the accessed field name */
    } field_addr;

    /* Specific payload for Calls / Syscalls */
    struct {
        IrOperand *args;
        uint32_t   arg_count;
        uint64_t   symbol_hash;
    } call_payload;

    IrInsn *next;
    IrInsn *prev;
};

typedef struct {
    uint32_t label_id;
    IrInsn  *head;
    IrInsn  *tail;
} IrBasicBlock;

typedef struct {
    const char     *name;
    uint64_t        symbol_hash;
    uint32_t        next_reg_id;
    uint32_t        next_label_id;
    IrInsn         *first_insn;
    IrInsn         *last_insn;
    uint32_t        insn_count;
    uint32_t        stack_frame_size;
} IrFunction;

typedef struct {
    IrFunction **functions;
    uint32_t     function_count;
    RuModule    *ast_module;
} IrModule;

/* ========================================================================= */
/*                          6. COMPILER API INTERFACES                       */
/* ========================================================================= */

/*
 * EIA Cryptographic Artifact Signature Block (112 bytes)
 * Stored inside `.eia_auth` for production artifact provenance & authentication.
 */
typedef struct {
    uint32_t magic;              /* 0x00: Constant 0x41555448 ('EISA' - EIA Signature Auth) */
    uint16_t version;            /* 0x04: Format version (1) */
    uint16_t key_epoch;          /* 0x06: Key rotation & anti-replay epoch */
    uint64_t public_key_id;      /* 0x08: 64-bit public key identifier */
    uint8_t  blake3_digest[32];  /* 0x10: Full 256-bit BLAKE3 artifact digest */
    uint8_t  signature[64];      /* 0x30: 512-bit cryptographic signature */
} __attribute__((packed)) EiaSignatureRecord;

#define EIA_AUTH_MAGIC            0x41555448U /* 'EISA' - EIA Signature Auth */
#define EIA_AUTH_VERSION          1U
#define EIA_DEFAULT_KEY_EPOCH     1U
#define EIA_TRUSTED_PUBKEY_ID     0x4549415F524F4F54ULL /* "EIA_ROOT" */
#define EIA_MIN_TRUSTED_EPOCH     1U

_Static_assert(sizeof(EiaSignatureRecord) == 112, "EiaSignatureRecord must be exactly 112 bytes");

uint64_t spark0_hash64(const void *data, size_t len);
uint64_t spark0_hash_str(const char *str);
uint64_t blake3_hash64(const uint8_t *buf, size_t len);
void     blake3_hash256(const uint8_t *buf, size_t len, uint8_t out_digest[32]);

void     spark0_format_type_sig(const RuType *t, char *buf, size_t cap);
uint64_t spark0_compute_fn_sig_hash(const RuFnDef *fn);
uint64_t spark0_compute_struct_layout_hash(const RuStructDef *sdef);
int      spark0_sign_digest(const uint8_t digest[32], uint16_t key_epoch, uint8_t out_sig[64]);
bool     spark0_verify_signature(const uint8_t digest[32], uint16_t key_epoch, uint64_t pubkey_id, const uint8_t sig[64]);

RuModule *spark0_parse(const char *source_text, const char *filename);
int spark0_compile_to_elf(RuModule *module, const char *output_path, int is_upbp, int target_arch);
int spark0_compile_to_elf_opt(RuModule *module, const char *output_path, int is_upbp, int target_arch, int is_signed);

#ifdef __cplusplus
}
#endif

#endif /* SPARK0_H */
