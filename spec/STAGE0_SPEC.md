# Sovereign Systems Programming Language (.rx)
## Stage-0 Seed Specification: `spark0` under Eternal Interface Architecture (EIA)

This specification defines the minimal seed bootstrap subset (`spark0`) of the sovereign `.rx` systems programming language, its Abstract Syntax Tree (AST), flat 3-address Intermediate Representation (IR), and the byte-level EIA/ELF64 binary memory layout required to self-host the Stage 1 compiler.

---

### 1. Minimal `spark0` Grammar Specification

`spark0` includes only the primitive mechanisms strictly necessary to implement a self-hosting compiler:
- **Aggregates & Signatures**: `struct`, `fn`, `extern fn`.
- **Fixed-width Integers**: `i64`, `u64`, `u32`, `u8`, `void`.
- **Pointers & Buffers**: `*T` (const raw pointer), `*mut T` (mutable raw pointer), `[T; N]` (fixed array).
- **Control Flow**: `if/else`, `while`, `return`.
- **System Boundaries**: Inline `syscall(...)` and `asm(...)` intrinsics.

#### 1.1 Formal EBNF Grammar

```ebnf
Module             ::= TopLevelItem* EOF ;

TopLevelItem       ::= StructDef
                     | FnDef
                     | ExternFnDecl ;

StructDef          ::= "struct" Identifier "{" ( FieldDef ( "," FieldDef )* ","? )? "}" ;
FieldDef           ::= Identifier ":" Type ;

FnDef              ::= "fn" Identifier "(" ( Param ( "," Param )* ","? )? ")" ( "->" Type )? Block ;
ExternFnDecl       ::= "extern" "fn" Identifier "(" ( Param ( "," Param )* ","? )? ")" ( "->" Type )? ";" ;
Param              ::= Identifier ":" Type ;

Type               ::= "i64" | "u64" | "u32" | "u8" | "void"
                     | "*" "mut"? Type
                     | "[" Type ";" IntegerLiteral "]"
                     | Identifier ;

Block              ::= "{" Statement* "}" ;

Statement          ::= "let" "mut"? Identifier ":" Type ( "=" Expr )? ";"
                     | LValue "=" Expr ";"
                     | "if" Expr Block ( "else" ( IfStmt | Block ) )?
                     | "while" Expr Block
                     | "return" Expr? ";"
                     | Expr ";" ;

LValue             ::= Identifier
                     | "*" LValue
                     | PostfixExpr "." Identifier
                     | PostfixExpr "[" Expr "]" ;

Expr               ::= LogicalOrExpr ;
LogicalOrExpr      ::= LogicalAndExpr ( "||" LogicalAndExpr )* ;
LogicalAndExpr     ::= BitwiseOrExpr ( "&&" BitwiseOrExpr )* ;
BitwiseOrExpr      ::= BitwiseXorExpr ( "|" BitwiseXorExpr )* ;
BitwiseXorExpr     ::= BitwiseAndExpr ( "^" BitwiseAndExpr )* ;
BitwiseAndExpr     ::= EqualityExpr ( "&" EqualityExpr )* ;
EqualityExpr       ::= RelationalExpr ( ( "==" | "!=" ) RelationalExpr )* ;
RelationalExpr     ::= ShiftExpr ( ( "<" | "<=" | ">" | ">=" ) ShiftExpr )* ;
ShiftExpr          ::= AdditiveExpr ( ( "<<" | ">>" ) AdditiveExpr )* ;
AdditiveExpr       ::= MultiplicativeExpr ( ( "+" | "-" ) MultiplicativeExpr )* ;
MultiplicativeExpr ::= CastExpr ( ( "*" | "/" | "%" ) CastExpr )* ;
CastExpr           ::= UnaryExpr ( "as" Type )* ;

UnaryExpr          ::= ( "-" | "!" | "~" | "*" | "&" | "&mut" ) UnaryExpr
                     | PostfixExpr ;

PostfixExpr        ::= PrimaryExpr (
                         "." Identifier
                       | "[" Expr "]"
                       | "(" ( Expr ( "," Expr )* ","? )? ")"
                       )* ;

PrimaryExpr        ::= Identifier
                     | IntegerLiteral
                     | CharLiteral
                     | StringLiteral
                     | "syscall" "(" Expr ( "," Expr )* ")"
                     | "asm" "(" StringLiteral ( "," Expr )* ")"
                     | "(" Expr ")" ;

Identifier         ::= [a-zA-Z_][a-zA-Z0-9_]* ;
IntegerLiteral     ::= [0-9]+ | "0x" [0-9a-fA-F]+ ;
CharLiteral        ::= "'" ( [^'\\] | "\\" . ) "'" ;
StringLiteral      ::= '"' ( [^"\\] | "\\" . )* '"' ;
```

---

### 2. AST Representation (in C99 / Stage-0 Bootstrap Substrate)

```c
#include <stdint.h>
#include <stdbool.h>

/* Source Coordinates */
typedef struct {
    uint32_t line;
    uint32_t col;
} SourcePos;

/* Type Representation */
typedef enum {
    TYPE_VOID,
    TYPE_I64,
    TYPE_U64,
    TYPE_U32,
    TYPE_U8,
    TYPE_PTR_CONST,
    TYPE_PTR_MUT,
    TYPE_ARRAY,
    TYPE_STRUCT
} RuTypeKind;

typedef struct RuType RuType;
typedef struct RuFieldDef RuFieldDef;

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
            const char  *name;
            uint64_t     struct_name_hash;
            uint32_t     field_count;
            RuFieldDef  *fields;
        } structure;
    } as;
};

struct RuFieldDef {
    const char *name;
    uint64_t    name_hash;   /* BLAKE3-64 hash of field name */
    RuType     *type;
    SourcePos   pos;
};

typedef struct {
    const char *name;
    uint64_t    name_hash;
    uint64_t    type_sig_hash;
    RuFieldDef *fields;
    uint32_t    field_count;
    SourcePos   pos;
} RuStructDef;

typedef struct {
    const char *name;
    RuType     *type;
    SourcePos   pos;
} RuParam;

/* Expression Hierarchy */
typedef enum {
    EXPR_INT_LIT,
    EXPR_STRING_LIT,
    EXPR_VAR,
    EXPR_BINARY,
    EXPR_UNARY,
    EXPR_FIELD_ACCESS, /* ptr.field -> lowered to IR_FIELD_ADDR */
    EXPR_INDEX,
    EXPR_CALL,
    EXPR_CAST,
    EXPR_SYSCALL,
    EXPR_INLINE_ASM
} RuExprKind;

typedef enum {
    BINOP_ADD, BINOP_SUB, BINOP_MUL, BINOP_DIV, BINOP_MOD,
    BINOP_BIT_AND, BINOP_BIT_OR, BINOP_BIT_XOR, BINOP_SHL, BINOP_SHR,
    BINOP_EQ, BINOP_NE, BINOP_LT, BINOP_LE, BINOP_GT, BINOP_GE,
    BINOP_LOG_AND, BINOP_LOG_OR
} RuBinOp;

typedef enum {
    UNOP_NEG, UNOP_NOT, UNOP_BIT_NOT, UNOP_DEREF, UNOP_ADDR_OF, UNOP_ADDR_MUT
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
            RuExpr     *base;
            const char *field_name;
            uint64_t    field_hash;
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

/* Statements & Declarations */
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
            RuExpr *expr;
        } return_stmt;
        struct {
            RuExpr *expr;
        } expr_stmt;
    } as;
};

typedef struct {
    const char  *name;
    uint64_t     symbol_hash;
    RuParam     *params;
    uint32_t     param_count;
    RuType      *return_type;
    RuStmt     **body;
    uint32_t     stmt_count;
    bool         is_extern;
    SourcePos    pos;
} RuFnDef;

typedef struct {
    RuStructDef **structs;
    uint32_t      struct_count;
    RuFnDef     **functions;
    uint32_t      function_count;
} RuModule;
```

---

### 3. Flat 3-Address IR & EIA Relocation Lowering

#### 3.1 Strict Invariant: No Hardcoded Field Offsets
Under EIA, struct field offsets **must never be baked into IR constants or machine code displacement literals** during compilation. Instead:
1. Every field access `ptr.field` lowers to:
   ```c
   dst_reg = IR_FIELD_ADDR(base_reg, type_hash, field_hash)
   ```
2. The code generator emits an instruction with an explicit 32-bit zero immediate hole:
   ```nasm
   lea dst_reg, [base_reg + 0x00000000]
   ```
3. A relocation entry is appended to `.eia_reloc` (`EiaRelocHole`), specifying the exact byte offset of the 32-bit hole, the target structural type hash, and the field hash.
4. At link or load time, the EIA resolver patches the 4 bytes in-place.

#### 3.2 IR Data Structures

```c
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
    IR_MOV,
    IR_CONST,
    IR_ADD, IR_SUB, IR_MUL, IR_DIV, IR_MOD,
    IR_BIT_AND, IR_BIT_OR, IR_BIT_XOR, IR_SHL, IR_SHR,
    IR_NEG, IR_BIT_NOT,
    IR_CMP_EQ, IR_CMP_NE, IR_CMP_LT, IR_CMP_LE, IR_CMP_GT, IR_CMP_GE,
    IR_JMP, IR_JMP_IF, IR_JMP_IF_NOT,
    IR_CALL, IR_RET, IR_SYSCALL,
    IR_ALLOCA, IR_LOAD, IR_STORE,
    IR_FIELD_ADDR,   /* dst = base + RelocHole(type_hash, field_hash) */
    IR_INLINE_ASM
} IrOpcode;

typedef struct IrInsn IrInsn;
struct IrInsn {
    IrOpcode   opcode;
    IrReg      dst;
    IrOperand  src1;
    IrOperand  src2;

    struct {
        uint64_t type_hash;
        uint64_t field_hash;
    } field_addr;

    struct {
        IrOperand *args;
        uint32_t   arg_count;
        uint64_t   symbol_hash;
    } call_payload;

    IrInsn *next;
    IrInsn *prev;
};
```

---

### 4. Byte-Level Memory Layouts

All structures are strictly packed (`__attribute__((packed))`) and guaranteed to match their exact byte footprints.

#### 4.1 64-Byte ELF64 Header (`Elf64Header`)
```
Offset  Size  Field          Type      Value / Description
--------------------------------------------------------------------------
0x00    16    e_ident        uint8[16] \x7FELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00
0x10    2     e_type         uint16_t  0x0002 (ET_EXEC) or 0x0003 (ET_DYN)
0x12    2     e_machine      uint16_t  0x003E (EM_X86_64)
0x14    4     e_version      uint32_t  0x00000001 (EV_CURRENT)
0x18    8     e_entry        uint64_t  Virtual execution entry address
0x20    8     e_phoff        uint64_t  Program header table file offset (0x40)
0x28    8     e_shoff        uint64_t  Section header table file offset
0x30    4     e_flags        uint32_t  0x00000000
0x34    2     e_ehsize       uint16_t  0x0040 (64 bytes)
0x36    2     e_phentsize    uint16_t  0x0038 (56 bytes)
0x38    2     e_phnum        uint16_t  Number of program headers
0x3A    2     e_shentsize    uint16_t  0x0040 (64 bytes)
0x3C    2     e_shnum        uint16_t  Number of section headers
0x3E    2     e_shstrndx     uint16_t  Section header string table index
--------------------------------------------------------------------------
Total Size: 64 bytes (0x40)
```

#### 4.2 56-Byte ELF64 Program Header (`Elf64ProgramHeader`)
```
Offset  Size  Field          Type      Description
--------------------------------------------------------------------------
0x00    4     p_type         uint32_t  Segment type (PT_LOAD=1, PT_NOTE=4)
0x04    4     p_flags        uint32_t  Segment flags (PF_X=1, PF_W=2, PF_R=4)
0x08    8     p_offset       uint64_t  File offset where segment begins
0x10    8     p_vaddr        uint64_t  Virtual memory load address
0x18    8     p_paddr        uint64_t  Physical address (0 for x86_64)
0x20    8     p_filesz       uint64_t  Segment size in file
0x28    8     p_memsz        uint64_t  Segment size in memory
0x30    8     p_align        uint64_t  Alignment (e.g., 0x1000 = 4KB)
--------------------------------------------------------------------------
Total Size: 56 bytes (0x38)
```

#### 4.3 96-Byte `UniversalHologramHeader`
```
Offset  Size  Field               Type        Description
--------------------------------------------------------------------------
0x00    4     magic               uint32_t    0x44484945 ('EIAH')
0x04    2     version_major       uint16_t    0x0002 (Version 2)
0x06    2     version_minor       uint16_t    0x0000 (Version 0)
0x08    8     abi_epoch           uint64_t    Monotonic ABI epoch counter
0x10    8     contracts_offset    uint64_t    Byte offset to .eia_contract
0x18    8     contracts_count     uint64_t    Total entries in SymbolContract array
0x20    8     relocs_offset       uint64_t    Byte offset to .eia_reloc
0x28    8     relocs_count        uint64_t    Total entries in EiaRelocHole array
0x30    8     type_graph_offset   uint64_t    Byte offset to serialized type graph
0x38    8     type_graph_size     uint64_t    Byte length of serialized type graph
0x40    8     blake3_root         uint64_t    BLAKE3-64 root hash of hologram interface
0x48    8     flags               uint64_t    Capability bitmask & execution policy
0x50    16    reserved            uint8[16]   Zeroed padding for 128-bit alignment
--------------------------------------------------------------------------
Total Size: 96 bytes (0x60)
```

#### 4.4 48-Byte `SymbolContract`
```
Offset  Size  Field               Type        Description
--------------------------------------------------------------------------
0x00    8     symbol_hash         uint64_t    BLAKE3-64 hash of symbol name string
0x08    8     type_sig_hash       uint64_t    BLAKE3-64 structural signature hash
0x10    8     vaddr               uint64_t    Virtual address or text offset
0x18    8     code_size           uint64_t    Byte length of symbol body
0x20    4     flags               uint32_t    EiaSymbolFlags (export, pure, inline)
0x24    2     param_count         uint16_t    Formal parameter count
0x26    2     calling_conv        uint16_t    0=System V AMD64, 1=EIA Sovereign
0x28    8     contract_digest     uint64_t    BLAKE3-64 verification digest
--------------------------------------------------------------------------
Total Size: 48 bytes (0x30)
```

#### 4.5 24-Byte `EiaRelocHole`
```
Offset  Size  Field               Type        Description
--------------------------------------------------------------------------
0x00    4     insn_offset         uint32_t    Byte offset of the 32-bit hole in .text
0x04    4     patch_kind          uint32_t    EiaPatchKind (1 = EIA_PATCH_FIELD_DISP32)
0x08    8     type_sig_hash       uint64_t    BLAKE3-64 structural type hash of struct
0x10    8     field_or_sym_hash   uint64_t    BLAKE3-64 hash of field name or symbol
--------------------------------------------------------------------------
Total Size: 24 bytes (0x18)
```
