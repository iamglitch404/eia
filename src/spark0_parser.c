#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "spark0_lexer.h"

/* ------------------------------------------------------------------------- */
/*                             Hash Functions                                */
/* ------------------------------------------------------------------------- */

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

static char *my_strdup(const char *s) {
    if (!s) return NULL;
    size_t l = strlen(s);
    char *d = (char *)malloc(l + 1);
    memcpy(d, s, l + 1);
    return d;
}

/* ------------------------------------------------------------------------- */
/*                                Parser State                               */
/* ------------------------------------------------------------------------- */

typedef struct {
    Lexer    lexer;
    Token    cur;
    RuModule module;
} Parser;

static void parser_advance(Parser *p) {
    token_free(&p->cur);
    p->cur = lexer_next(&p->lexer);
}

static bool check(Parser *p, RuTokenType type) {
    return p->cur.type == type;
}

static bool match(Parser *p, RuTokenType type) {
    if (check(p, type)) {
        parser_advance(p);
        return true;
    }
    return false;
}

static void expect(Parser *p, RuTokenType type, const char *msg) {
    if (!check(p, type)) {
        fprintf(stderr, "%s:%u:%u: Parse error: %s (got '%s')\n",
                p->lexer.filename, p->cur.pos.line, p->cur.pos.col, msg,
                p->cur.text ? p->cur.text : "<unknown>");
        exit(1);
    }
    parser_advance(p);
}

/* Forward declarations */
static RuType *parse_type(Parser *p);
static RuExpr *parse_expr(Parser *p);
static RuStmt *parse_stmt(Parser *p);

/* ------------------------------------------------------------------------- */
/*                                Type Parsing                               */
/* ------------------------------------------------------------------------- */

static RuType *alloc_type(RuTypeKind kind) {
    RuType *t = (RuType *)calloc(1, sizeof(RuType));
    t->kind = kind;
    switch (kind) {
        case TYPE_I64:
        case TYPE_U64:
        case TYPE_PTR_CONST:
        case TYPE_PTR_MUT:
            t->size_bytes = 8;
            t->align_bytes = 8;
            break;
        case TYPE_I32:
        case TYPE_U32:
            t->size_bytes = 4;
            t->align_bytes = 4;
            break;
        case TYPE_U8:
            t->size_bytes = 1;
            t->align_bytes = 1;
            break;
        case TYPE_VOID:
        default:
            t->size_bytes = 0;
            t->align_bytes = 1;
            break;
    }
    return t;
}

static RuType *parse_type(Parser *p) {
    if (match(p, TOKEN_TYPE_I64)) return alloc_type(TYPE_I64);
    if (match(p, TOKEN_TYPE_U64)) return alloc_type(TYPE_U64);
    if (match(p, TOKEN_TYPE_I32)) return alloc_type(TYPE_I32);
    if (match(p, TOKEN_TYPE_U32)) return alloc_type(TYPE_U32);
    if (match(p, TOKEN_TYPE_U8))  return alloc_type(TYPE_U8);
    if (match(p, TOKEN_TYPE_VOID)) return alloc_type(TYPE_VOID);

    if (match(p, TOKEN_STAR)) {
        bool is_mut = match(p, TOKEN_MUT);
        RuType *t = alloc_type(is_mut ? TYPE_PTR_MUT : TYPE_PTR_CONST);
        t->as.ptr.pointee = parse_type(p);
        t->type_sig_hash = spark0_hash_str(is_mut ? "*mut" : "*");
        if (t->as.ptr.pointee) {
            t->type_sig_hash ^= t->as.ptr.pointee->type_sig_hash;
        }
        return t;
    }

    if (match(p, TOKEN_LBRACKET)) {
        RuType *elem_t = parse_type(p);
        expect(p, TOKEN_SEMICOLON, "expected ';' in array type [T; N]");
        if (!check(p, TOKEN_INT_LIT)) {
            fprintf(stderr, "%s:%u:%u: expected integer array length\n",
                    p->lexer.filename, p->cur.pos.line, p->cur.pos.col);
            exit(1);
        }
        uint64_t count = p->cur.int_val;
        parser_advance(p);
        expect(p, TOKEN_RBRACKET, "expected ']' in array type");

        RuType *t = alloc_type(TYPE_ARRAY);
        t->as.array.elem_type = elem_t;
        t->as.array.count = count;
        t->size_bytes = (uint32_t)(elem_t->size_bytes * count);
        t->align_bytes = elem_t->align_bytes;
        return t;
    }

    if (check(p, TOKEN_IDENT)) {
        char *name = my_strdup(p->cur.text);
        parser_advance(p);
        RuType *t = alloc_type(TYPE_STRUCT);
        t->as.structure.name = name;
        t->as.structure.struct_name_hash = spark0_hash_str(name);
        t->type_sig_hash = t->as.structure.struct_name_hash;
        return t;
    }

    fprintf(stderr, "%s:%u:%u: expected type name\n",
            p->lexer.filename, p->cur.pos.line, p->cur.pos.col);
    exit(1);
}

/* ------------------------------------------------------------------------- */
/*                            Expression Parsing                             */
/* ------------------------------------------------------------------------- */

static RuExpr *alloc_expr(RuExprKind kind, SourcePos pos) {
    RuExpr *e = (RuExpr *)calloc(1, sizeof(RuExpr));
    e->kind = kind;
    e->pos = pos;
    return e;
}

static RuExpr *parse_primary(Parser *p) {
    SourcePos pos = p->cur.pos;

    if (check(p, TOKEN_INT_LIT)) {
        RuExpr *e = alloc_expr(EXPR_INT_LIT, pos);
        e->as.int_val = p->cur.int_val;
        e->resolved_type = alloc_type(TYPE_U64);
        parser_advance(p);
        return e;
    }

    if (check(p, TOKEN_CHAR_LIT)) {
        RuExpr *e = alloc_expr(EXPR_INT_LIT, pos);
        e->as.int_val = p->cur.int_val;
        e->resolved_type = alloc_type(TYPE_U8);
        parser_advance(p);
        return e;
    }

    if (check(p, TOKEN_STRING_LIT)) {
        RuExpr *e = alloc_expr(EXPR_STRING_LIT, pos);
        e->as.str.str_val = my_strdup(p->cur.str_val);
        e->as.str.str_len = p->cur.str_len;
        RuType *pt = alloc_type(TYPE_PTR_CONST);
        pt->as.ptr.pointee = alloc_type(TYPE_U8);
        e->resolved_type = pt;
        parser_advance(p);
        return e;
    }

    if (match(p, TOKEN_SYSCALL)) {
        expect(p, TOKEN_LPAREN, "expected '(' after syscall");
        RuExpr *e = alloc_expr(EXPR_SYSCALL, pos);
        e->resolved_type = alloc_type(TYPE_I64);

        RuExpr **args = NULL;
        uint32_t cap = 0, count = 0;

        if (!check(p, TOKEN_RPAREN)) {
            while (1) {
                if (count >= cap) {
                    cap = cap ? cap * 2 : 4;
                    args = (RuExpr **)realloc(args, cap * sizeof(RuExpr *));
                }
                args[count++] = parse_expr(p);
                if (!match(p, TOKEN_COMMA)) break;
            }
        }
        expect(p, TOKEN_RPAREN, "expected ')' after syscall args");
        if (count == 0) {
            fprintf(stderr, "%s:%u:%u: syscall requires at least syscall number\n",
                    p->lexer.filename, pos.line, pos.col);
            exit(1);
        }
        e->as.syscall.nr = args[0];
        e->as.syscall.args = (count > 1) ? &args[1] : NULL;
        e->as.syscall.num_args = count - 1;
        return e;
    }

    if (match(p, TOKEN_ASM)) {
        expect(p, TOKEN_LPAREN, "expected '(' after asm");
        if (!check(p, TOKEN_STRING_LIT)) {
            fprintf(stderr, "%s:%u:%u: asm requires string template\n",
                    p->lexer.filename, pos.line, pos.col);
            exit(1);
        }
        RuExpr *e = alloc_expr(EXPR_INLINE_ASM, pos);
        e->as.inline_asm.template_str = my_strdup(p->cur.str_val);
        parser_advance(p);

        RuExpr **ops = NULL;
        uint32_t cap = 0, count = 0;
        while (match(p, TOKEN_COMMA)) {
            if (count >= cap) {
                cap = cap ? cap * 2 : 4;
                ops = (RuExpr **)realloc(ops, cap * sizeof(RuExpr *));
            }
            ops[count++] = parse_expr(p);
        }
        expect(p, TOKEN_RPAREN, "expected ')' after asm operands");
        e->as.inline_asm.operands = ops;
        e->as.inline_asm.num_operands = count;
        e->resolved_type = alloc_type(TYPE_VOID);
        return e;
    }

    if (check(p, TOKEN_IDENT)) {
        RuExpr *e = alloc_expr(EXPR_VAR, pos);
        e->as.var_name = my_strdup(p->cur.text);
        parser_advance(p);
        return e;
    }

    if (match(p, TOKEN_LPAREN)) {
        RuExpr *e = parse_expr(p);
        expect(p, TOKEN_RPAREN, "expected ')'");
        return e;
    }

    fprintf(stderr, "%s:%u:%u: unexpected token in primary expression: '%s'\n",
            p->lexer.filename, pos.line, pos.col, p->cur.text ? p->cur.text : "<unknown>");
    exit(1);
}

static RuExpr *parse_postfix(Parser *p) {
    RuExpr *e = parse_primary(p);

    while (1) {
        SourcePos pos = p->cur.pos;
        if (match(p, TOKEN_DOT)) {
            /* Field Access: ptr.field */
            if (!check(p, TOKEN_IDENT)) {
                fprintf(stderr, "%s:%u:%u: expected field name after '.'\n",
                        p->lexer.filename, pos.line, pos.col);
                exit(1);
            }
            RuExpr *fa = alloc_expr(EXPR_FIELD_ACCESS, pos);
            fa->as.field_access.base = e;
            fa->as.field_access.field_name = my_strdup(p->cur.text);
            fa->as.field_access.field_hash = spark0_hash_str(p->cur.text);
            parser_advance(p);
            e = fa;
        } else if (match(p, TOKEN_LBRACKET)) {
            RuExpr *idx = parse_expr(p);
            expect(p, TOKEN_RBRACKET, "expected ']' after array index");
            RuExpr *ie = alloc_expr(EXPR_INDEX, pos);
            ie->as.index.base = e;
            ie->as.index.index = idx;
            e = ie;
        } else if (match(p, TOKEN_LPAREN)) {
            /* Function Call */
            RuExpr *call = alloc_expr(EXPR_CALL, pos);
            call->as.call.callee = e;
            RuExpr **args = NULL;
            uint32_t cap = 0, count = 0;
            if (!check(p, TOKEN_RPAREN)) {
                while (1) {
                    if (count >= cap) {
                        cap = cap ? cap * 2 : 4;
                        args = (RuExpr **)realloc(args, cap * sizeof(RuExpr *));
                    }
                    args[count++] = parse_expr(p);
                    if (!match(p, TOKEN_COMMA)) break;
                }
            }
            expect(p, TOKEN_RPAREN, "expected ')' after arguments");
            call->as.call.args = args;
            call->as.call.num_args = count;
            e = call;
        } else {
            break;
        }
    }
    return e;
}

static RuExpr *parse_unary(Parser *p) {
    SourcePos pos = p->cur.pos;

    if (match(p, TOKEN_MINUS)) {
        RuExpr *e = alloc_expr(EXPR_UNARY, pos);
        e->as.unary.op = UNOP_NEG;
        e->as.unary.operand = parse_unary(p);
        return e;
    }
    if (match(p, TOKEN_EXCL)) {
        RuExpr *e = alloc_expr(EXPR_UNARY, pos);
        e->as.unary.op = UNOP_NOT;
        e->as.unary.operand = parse_unary(p);
        return e;
    }
    if (match(p, TOKEN_TILDE)) {
        RuExpr *e = alloc_expr(EXPR_UNARY, pos);
        e->as.unary.op = UNOP_BIT_NOT;
        e->as.unary.operand = parse_unary(p);
        return e;
    }
    if (match(p, TOKEN_STAR)) {
        RuExpr *e = alloc_expr(EXPR_UNARY, pos);
        e->as.unary.op = UNOP_DEREF;
        e->as.unary.operand = parse_unary(p);
        return e;
    }
    if (match(p, TOKEN_AMP)) {
        bool is_mut = match(p, TOKEN_MUT);
        RuExpr *e = alloc_expr(EXPR_UNARY, pos);
        e->as.unary.op = is_mut ? UNOP_ADDR_MUT : UNOP_ADDR_OF;
        e->as.unary.operand = parse_unary(p);
        return e;
    }

    return parse_postfix(p);
}

static RuExpr *parse_cast(Parser *p) {
    RuExpr *e = parse_unary(p);
    while (match(p, TOKEN_AS)) {
        SourcePos pos = p->cur.pos;
        RuType *target_t = parse_type(p);
        RuExpr *c = alloc_expr(EXPR_CAST, pos);
        c->as.cast.expr = e;
        c->as.cast.target_type = target_t;
        c->resolved_type = target_t;
        e = c;
    }
    return e;
}

static RuExpr *parse_mul(Parser *p) {
    RuExpr *e = parse_cast(p);
    while (check(p, TOKEN_STAR) || check(p, TOKEN_SLASH) || check(p, TOKEN_PERCENT)) {
        SourcePos pos = p->cur.pos;
        RuBinOp op = check(p, TOKEN_STAR) ? BINOP_MUL :
                     check(p, TOKEN_SLASH) ? BINOP_DIV : BINOP_MOD;
        parser_advance(p);
        RuExpr *rhs = parse_cast(p);
        RuExpr *bin = alloc_expr(EXPR_BINARY, pos);
        bin->as.binary.op = op;
        bin->as.binary.lhs = e;
        bin->as.binary.rhs = rhs;
        e = bin;
    }
    return e;
}

static RuExpr *parse_add(Parser *p) {
    RuExpr *e = parse_mul(p);
    while (check(p, TOKEN_PLUS) || check(p, TOKEN_MINUS)) {
        SourcePos pos = p->cur.pos;
        RuBinOp op = check(p, TOKEN_PLUS) ? BINOP_ADD : BINOP_SUB;
        parser_advance(p);
        RuExpr *rhs = parse_mul(p);
        RuExpr *bin = alloc_expr(EXPR_BINARY, pos);
        bin->as.binary.op = op;
        bin->as.binary.lhs = e;
        bin->as.binary.rhs = rhs;
        e = bin;
    }
    return e;
}

static RuExpr *parse_shift(Parser *p) {
    RuExpr *e = parse_add(p);
    while (check(p, TOKEN_SHL) || check(p, TOKEN_SHR)) {
        SourcePos pos = p->cur.pos;
        RuBinOp op = check(p, TOKEN_SHL) ? BINOP_SHL : BINOP_SHR;
        parser_advance(p);
        RuExpr *rhs = parse_add(p);
        RuExpr *bin = alloc_expr(EXPR_BINARY, pos);
        bin->as.binary.op = op;
        bin->as.binary.lhs = e;
        bin->as.binary.rhs = rhs;
        e = bin;
    }
    return e;
}

static RuExpr *parse_relational(Parser *p) {
    RuExpr *e = parse_shift(p);
    while (check(p, TOKEN_LT) || check(p, TOKEN_LTE) || check(p, TOKEN_GT) || check(p, TOKEN_GTE)) {
        SourcePos pos = p->cur.pos;
        RuBinOp op = check(p, TOKEN_LT)  ? BINOP_LT :
                     check(p, TOKEN_LTE) ? BINOP_LE :
                     check(p, TOKEN_GT)  ? BINOP_GT : BINOP_GE;
        parser_advance(p);
        RuExpr *rhs = parse_shift(p);
        RuExpr *bin = alloc_expr(EXPR_BINARY, pos);
        bin->as.binary.op = op;
        bin->as.binary.lhs = e;
        bin->as.binary.rhs = rhs;
        e = bin;
    }
    return e;
}

static RuExpr *parse_equality(Parser *p) {
    RuExpr *e = parse_relational(p);
    while (check(p, TOKEN_EQEQ) || check(p, TOKEN_NEQ)) {
        SourcePos pos = p->cur.pos;
        RuBinOp op = check(p, TOKEN_EQEQ) ? BINOP_EQ : BINOP_NE;
        parser_advance(p);
        RuExpr *rhs = parse_relational(p);
        RuExpr *bin = alloc_expr(EXPR_BINARY, pos);
        bin->as.binary.op = op;
        bin->as.binary.lhs = e;
        bin->as.binary.rhs = rhs;
        e = bin;
    }
    return e;
}

static RuExpr *parse_bitand(Parser *p) {
    RuExpr *e = parse_equality(p);
    while (match(p, TOKEN_AMP)) {
        SourcePos pos = p->cur.pos;
        RuExpr *rhs = parse_equality(p);
        RuExpr *bin = alloc_expr(EXPR_BINARY, pos);
        bin->as.binary.op = BINOP_BIT_AND;
        bin->as.binary.lhs = e;
        bin->as.binary.rhs = rhs;
        e = bin;
    }
    return e;
}

static RuExpr *parse_bitxor(Parser *p) {
    RuExpr *e = parse_bitand(p);
    while (match(p, TOKEN_CARET)) {
        SourcePos pos = p->cur.pos;
        RuExpr *rhs = parse_bitand(p);
        RuExpr *bin = alloc_expr(EXPR_BINARY, pos);
        bin->as.binary.op = BINOP_BIT_XOR;
        bin->as.binary.lhs = e;
        bin->as.binary.rhs = rhs;
        e = bin;
    }
    return e;
}

static RuExpr *parse_bitor(Parser *p) {
    RuExpr *e = parse_bitxor(p);
    while (match(p, TOKEN_PIPE)) {
        SourcePos pos = p->cur.pos;
        RuExpr *rhs = parse_bitxor(p);
        RuExpr *bin = alloc_expr(EXPR_BINARY, pos);
        bin->as.binary.op = BINOP_BIT_OR;
        bin->as.binary.lhs = e;
        bin->as.binary.rhs = rhs;
        e = bin;
    }
    return e;
}

static RuExpr *parse_and(Parser *p) {
    RuExpr *e = parse_bitor(p);
    while (match(p, TOKEN_AMPAMP)) {
        SourcePos pos = p->cur.pos;
        RuExpr *rhs = parse_bitor(p);
        RuExpr *bin = alloc_expr(EXPR_BINARY, pos);
        bin->as.binary.op = BINOP_LOG_AND;
        bin->as.binary.lhs = e;
        bin->as.binary.rhs = rhs;
        e = bin;
    }
    return e;
}

static RuExpr *parse_or(Parser *p) {
    RuExpr *e = parse_and(p);
    while (match(p, TOKEN_PIPEPIPE)) {
        SourcePos pos = p->cur.pos;
        RuExpr *rhs = parse_and(p);
        RuExpr *bin = alloc_expr(EXPR_BINARY, pos);
        bin->as.binary.op = BINOP_LOG_OR;
        bin->as.binary.lhs = e;
        bin->as.binary.rhs = rhs;
        e = bin;
    }
    return e;
}

static RuExpr *parse_expr(Parser *p) {
    return parse_or(p);
}

/* ------------------------------------------------------------------------- */
/*                             Statement Parsing                             */
/* ------------------------------------------------------------------------- */

static RuStmt *alloc_stmt(RuStmtKind kind, SourcePos pos) {
    RuStmt *s = (RuStmt *)calloc(1, sizeof(RuStmt));
    s->kind = kind;
    s->pos = pos;
    return s;
}

static RuStmt **parse_block_stmts(Parser *p, uint32_t *count_out) {
    expect(p, TOKEN_LBRACE, "expected '{' for block");
    RuStmt **stmts = NULL;
    uint32_t cap = 0, count = 0;

    while (!check(p, TOKEN_RBRACE) && !check(p, TOKEN_EOF)) {
        if (count >= cap) {
            cap = cap ? cap * 2 : 8;
            stmts = (RuStmt **)realloc(stmts, cap * sizeof(RuStmt *));
        }
        stmts[count++] = parse_stmt(p);
    }
    expect(p, TOKEN_RBRACE, "expected '}' after block");
    *count_out = count;
    return stmts;
}

static RuStmt *parse_stmt(Parser *p) {
    SourcePos pos = p->cur.pos;

    if (match(p, TOKEN_LET)) {
        bool is_mut = match(p, TOKEN_MUT);
        if (!check(p, TOKEN_IDENT)) {
            fprintf(stderr, "%s:%u:%u: expected variable name after let\n",
                    p->lexer.filename, pos.line, pos.col);
            exit(1);
        }
        char *name = my_strdup(p->cur.text);
        parser_advance(p);

        expect(p, TOKEN_COLON, "expected ':' after variable name");
        RuType *t = parse_type(p);

        RuExpr *init = NULL;
        if (match(p, TOKEN_EQ)) {
            init = parse_expr(p);
        }
        expect(p, TOKEN_SEMICOLON, "expected ';' after let statement");

        RuStmt *s = alloc_stmt(STMT_LET, pos);
        s->as.let_stmt.name = name;
        s->as.let_stmt.is_mut = is_mut;
        s->as.let_stmt.type = t;
        s->as.let_stmt.init = init;
        return s;
    }

    if (match(p, TOKEN_IF)) {
        RuExpr *cond = parse_expr(p);
        uint32_t then_cnt = 0;
        RuStmt **then_stmts = parse_block_stmts(p, &then_cnt);

        uint32_t else_cnt = 0;
        RuStmt **else_stmts = NULL;
        if (match(p, TOKEN_ELSE)) {
            if (check(p, TOKEN_IF)) {
                else_cnt = 1;
                else_stmts = (RuStmt **)malloc(sizeof(RuStmt *));
                else_stmts[0] = parse_stmt(p);
            } else {
                else_stmts = parse_block_stmts(p, &else_cnt);
            }
        }

        RuStmt *s = alloc_stmt(STMT_IF, pos);
        s->as.if_stmt.cond = cond;
        s->as.if_stmt.then_stmts = then_stmts;
        s->as.if_stmt.then_count = then_cnt;
        s->as.if_stmt.else_stmts = else_stmts;
        s->as.if_stmt.else_count = else_cnt;
        return s;
    }

    if (match(p, TOKEN_WHILE)) {
        RuExpr *cond = parse_expr(p);
        uint32_t body_cnt = 0;
        RuStmt **body_stmts = parse_block_stmts(p, &body_cnt);

        RuStmt *s = alloc_stmt(STMT_WHILE, pos);
        s->as.while_stmt.cond = cond;
        s->as.while_stmt.body_stmts = body_stmts;
        s->as.while_stmt.body_count = body_cnt;
        return s;
    }

    if (match(p, TOKEN_RETURN)) {
        RuExpr *expr = NULL;
        if (!check(p, TOKEN_SEMICOLON)) {
            expr = parse_expr(p);
        }
        expect(p, TOKEN_SEMICOLON, "expected ';' after return");
        RuStmt *s = alloc_stmt(STMT_RETURN, pos);
        s->as.return_stmt.expr = expr;
        return s;
    }

    /* Assignment or Expression statement */
    RuExpr *expr = parse_expr(p);
    if (match(p, TOKEN_EQ)) {
        RuExpr *rhs = parse_expr(p);
        expect(p, TOKEN_SEMICOLON, "expected ';' after assignment");
        RuStmt *s = alloc_stmt(STMT_ASSIGN, pos);
        s->as.assign_stmt.lhs = expr;
        s->as.assign_stmt.rhs = rhs;
        return s;
    }

    expect(p, TOKEN_SEMICOLON, "expected ';' after expression");
    RuStmt *s = alloc_stmt(STMT_EXPR, pos);
    s->as.expr_stmt.expr = expr;
    return s;
}

/* ------------------------------------------------------------------------- */
/*                          Top-Level Items Parsing                          */
/* ------------------------------------------------------------------------- */

static RuStructDef *parse_struct_def(Parser *p) {
    SourcePos pos = p->cur.pos;
    expect(p, TOKEN_STRUCT, "expected 'struct'");
    if (!check(p, TOKEN_IDENT)) {
        fprintf(stderr, "%s:%u:%u: expected struct name\n",
                p->lexer.filename, pos.line, pos.col);
        exit(1);
    }
    char *sname = my_strdup(p->cur.text);
    parser_advance(p);
    expect(p, TOKEN_LBRACE, "expected '{' for struct body");

    RuFieldDef *fields = NULL;
    uint32_t cap = 0, count = 0;

    while (!check(p, TOKEN_RBRACE) && !check(p, TOKEN_EOF)) {
        if (!check(p, TOKEN_IDENT)) {
            fprintf(stderr, "%s:%u:%u: expected field name in struct\n",
                    p->lexer.filename, p->cur.pos.line, p->cur.pos.col);
            exit(1);
        }
        char *fname = my_strdup(p->cur.text);
        SourcePos fpos = p->cur.pos;
        parser_advance(p);

        expect(p, TOKEN_COLON, "expected ':' after field name");
        RuType *ftype = parse_type(p);

        if (count >= cap) {
            cap = cap ? cap * 2 : 4;
            fields = (RuFieldDef *)realloc(fields, cap * sizeof(RuFieldDef));
        }
        fields[count].name = fname;
        fields[count].name_hash = spark0_hash_str(fname);
        fields[count].type = ftype;
        fields[count].pos = fpos;
        count++;

        if (match(p, TOKEN_COMMA)) {
            if (check(p, TOKEN_RBRACE)) break;
        } else {
            if (!check(p, TOKEN_RBRACE)) {
                expect(p, TOKEN_COMMA, "expected ',' or '}' in struct");
            }
        }
    }
    expect(p, TOKEN_RBRACE, "expected '}' after struct body");

    RuStructDef *sdef = (RuStructDef *)calloc(1, sizeof(RuStructDef));
    sdef->name = sname;
    sdef->name_hash = spark0_hash_str(sname);
    sdef->fields = fields;
    sdef->field_count = count;
    sdef->pos = pos;

    /* Canonical structural type signature hash */
    sdef->type_sig_hash = sdef->name_hash;
    sdef->layout_hash = spark0_compute_struct_layout_hash(sdef);

    return sdef;
}

static uint64_t get_canonical_type_hash(const RuType *t, uint32_t *is_ptr_out);

static uint64_t get_canonical_type_hash(const RuType *t, uint32_t *is_ptr_out);

uint64_t spark0_compute_struct_layout_hash(const RuStructDef *sdef) {
    if (!sdef) return 0;
    if (sdef->field_count == 0) return spark0_hash_str("struct{}");

    uint32_t total_size = 0;
    uint32_t max_align = 8;
    for (uint32_t i = 0; i < sdef->field_count; ++i) {
        uint32_t sz = sdef->fields[i].type ? sdef->fields[i].type->size_bytes : 8;
        if (sz == 0) sz = 8;
        total_size += sz;
    }

    size_t header_len = 16;
    size_t fields_len = (size_t)sdef->field_count * 24;
    size_t total_len = header_len + fields_len;
    uint8_t *buf = (uint8_t *)calloc(total_len, 1);

    /* Header: [field_count: u32] [total_size: u32] [alignment: u32] [flags: u32] */
    uint32_t fc = sdef->field_count;
    memcpy(buf + 0, &fc, 4);
    memcpy(buf + 4, &total_size, 4);
    memcpy(buf + 8, &max_align, 4);
    /* buf + 12: flags = 0 */

    uint32_t cur_offset = 0;
    for (uint32_t i = 0; i < sdef->field_count; ++i) {
        uint8_t *rec = buf + header_len + (i * 24);
        uint64_t f_name_h = sdef->fields[i].name_hash;
        uint64_t f_type_h = get_canonical_type_hash(sdef->fields[i].type, NULL);
        uint32_t f_sz = sdef->fields[i].type ? sdef->fields[i].type->size_bytes : 8;
        if (f_sz == 0) f_sz = 8;
        uint32_t f_off = cur_offset;
        cur_offset += f_sz;

        memcpy(rec + 0, &f_name_h, 8);
        memcpy(rec + 8, &f_type_h, 8);
        memcpy(rec + 16, &f_off, 4);
        memcpy(rec + 20, &f_sz, 4);
    }

    uint64_t h = blake3_hash64(buf, total_len);
    free(buf);
    return h;
}

static uint64_t get_canonical_type_hash(const RuType *t, uint32_t *is_ptr_out) {
    if (!t || t->kind == TYPE_VOID) {
        if (is_ptr_out) *is_ptr_out = 0;
        return 3563412735833858527ULL; /* spark0_hash_str("void") */
    }

    /* Nested pointer depth & mutability encoding: if depth <= 1: mut_flag (1 or 2); if depth > 1: (depth << 2) | mut_flag */
    if (t->kind == TYPE_PTR_MUT || t->kind == TYPE_PTR_CONST) {
        uint32_t depth = 0;
        uint32_t mut_flag = (t->kind == TYPE_PTR_MUT) ? 2 : 1;
        const RuType *cur = t;
        while (cur && (cur->kind == TYPE_PTR_MUT || cur->kind == TYPE_PTR_CONST)) {
            depth++;
            if (cur->kind == TYPE_PTR_MUT) mut_flag = 2;
            cur = cur->as.ptr.pointee;
        }
        if (is_ptr_out) {
            *is_ptr_out = (depth <= 1) ? mut_flag : ((depth << 2) | (mut_flag & 0x3));
        }
        return get_canonical_type_hash(cur, NULL);
    }

    if (is_ptr_out) *is_ptr_out = 0;

    /* Fixed-size arrays: [T; N] */
    if (t->kind == TYPE_ARRAY) {
        uint64_t elem_hash = get_canonical_type_hash(t->as.array.elem_type, NULL);
        uint8_t arr_buf[24];
        memset(arr_buf, 0, sizeof(arr_buf));
        uint32_t kind = 0x0A; /* TYPE_ARRAY */
        uint64_t cnt = t->as.array.count;
        memcpy(arr_buf + 0, &kind, 4);
        memcpy(arr_buf + 4, &elem_hash, 8);
        memcpy(arr_buf + 12, &cnt, 8);
        return blake3_hash64(arr_buf, sizeof(arr_buf));
    }

    /* Full documented primitive set */
    switch (t->kind) {
        case TYPE_I64:  return 3089943341986682694ULL;
        case TYPE_U64:  return 5563585020063213298ULL;
        case TYPE_I32:  return 3094732814638223685ULL;
        case TYPE_U32:  return 5560783464435099345ULL;
        case TYPE_I16:  return 3092775683940386555ULL;
        case TYPE_U16:  return 5558799945458185151ULL;
        case TYPE_I8:   return 627981701265227156ULL;
        case TYPE_U8:   return 631772817358541784ULL;
        case TYPE_F64:  return 15957463049929925035ULL;
        case TYPE_F32:  return 15952682373371409732ULL;
        case TYPE_BOOL: return 14785269867199075517ULL;
        case TYPE_STRUCT:
            return spark0_hash_str(t->as.structure.name ? t->as.structure.name : "anon");
        default:
            return spark0_hash_str(t->as.structure.name ? t->as.structure.name : "unknown");
    }
}

void spark0_format_type_sig(const RuType *t, char *buf, size_t cap) {
    if (!t) {
        snprintf(buf, cap, "void");
        return;
    }
    switch (t->kind) {
        case TYPE_VOID: snprintf(buf, cap, "void"); break;
        case TYPE_I64:  snprintf(buf, cap, "i64"); break;
        case TYPE_U64:  snprintf(buf, cap, "u64"); break;
        case TYPE_I32:  snprintf(buf, cap, "i32"); break;
        case TYPE_U32:  snprintf(buf, cap, "u32"); break;
        case TYPE_I16:  snprintf(buf, cap, "i16"); break;
        case TYPE_U16:  snprintf(buf, cap, "u16"); break;
        case TYPE_I8:   snprintf(buf, cap, "i8"); break;
        case TYPE_U8:   snprintf(buf, cap, "u8"); break;
        case TYPE_F64:  snprintf(buf, cap, "f64"); break;
        case TYPE_F32:  snprintf(buf, cap, "f32"); break;
        case TYPE_BOOL: snprintf(buf, cap, "bool"); break;
        case TYPE_PTR_CONST: {
            char sub[256];
            spark0_format_type_sig(t->as.ptr.pointee, sub, sizeof(sub));
            snprintf(buf, cap, "*const(%s)", sub);
            break;
        }
        case TYPE_PTR_MUT: {
            char sub[256];
            spark0_format_type_sig(t->as.ptr.pointee, sub, sizeof(sub));
            snprintf(buf, cap, "*mut(%s)", sub);
            break;
        }
        case TYPE_ARRAY: {
            char sub[256];
            spark0_format_type_sig(t->as.array.elem_type, sub, sizeof(sub));
            snprintf(buf, cap, "[%s;%llu]", sub, (unsigned long long)t->as.array.count);
            break;
        }
        case TYPE_STRUCT:
            snprintf(buf, cap, "struct(%s)", t->as.structure.name ? t->as.structure.name : "anon");
            break;
        default:
            snprintf(buf, cap, "unknown");
            break;
    }
}

uint64_t spark0_compute_fn_sig_hash(const RuFnDef *fn) {
    if (!fn) return 0;
    uint32_t param_cnt = fn->param_count;
    size_t total_len = 16 + ((size_t)param_cnt * 16);
    uint8_t *sig_buf = (uint8_t *)calloc(total_len > 16 ? total_len : 16, 1);

    uint32_t is_ret_ptr = 0;
    uint64_t ret_type_hash = get_canonical_type_hash(fn->return_type, &is_ret_ptr);

    // Bytes 0..3: param_cnt (LE)
    sig_buf[0] = (uint8_t)(param_cnt & 0xFF);
    sig_buf[1] = (uint8_t)((param_cnt >> 8) & 0xFF);
    sig_buf[2] = (uint8_t)((param_cnt >> 16) & 0xFF);
    sig_buf[3] = (uint8_t)((param_cnt >> 24) & 0xFF);

    // Bytes 4..7: calling_conv (LE)
    uint32_t calling_conv = fn->calling_conv;
    sig_buf[4] = (uint8_t)(calling_conv & 0xFF);
    sig_buf[5] = (uint8_t)((calling_conv >> 8) & 0xFF);
    sig_buf[6] = (uint8_t)((calling_conv >> 16) & 0xFF);
    sig_buf[7] = (uint8_t)((calling_conv >> 24) & 0xFF);

    // Bytes 8..15: ret_type_hash (LE)
    for (int b = 0; b < 8; ++b) {
        sig_buf[8 + b] = (uint8_t)((ret_type_hash >> (b * 8)) & 0xFF);
    }

    // Bytes 16 + i*16 .. : params
    for (uint32_t i = 0; i < param_cnt; ++i) {
        uint32_t is_ptr = 0;
        uint64_t type_hash = get_canonical_type_hash(fn->params[i].type, &is_ptr);
        size_t base = 16 + (size_t)i * 16;
        for (int b = 0; b < 8; ++b) {
            sig_buf[base + b] = (uint8_t)((type_hash >> (b * 8)) & 0xFF);
            sig_buf[base + 8 + b] = (uint8_t)(((uint64_t)is_ptr >> (b * 8)) & 0xFF);
        }
    }

    uint64_t h = blake3_hash64(sig_buf, total_len);
    free(sig_buf);
    return h;
}

static RuFnDef *parse_fn_def(Parser *p, bool is_extern, uint16_t calling_conv) {
    SourcePos pos = p->cur.pos;
    expect(p, TOKEN_FN, "expected 'fn'");
    if (!check(p, TOKEN_IDENT)) {
        fprintf(stderr, "%s:%u:%u: expected function name\n",
                p->lexer.filename, pos.line, pos.col);
        exit(1);
    }
    char *fn_name = my_strdup(p->cur.text);
    parser_advance(p);

    expect(p, TOKEN_LPAREN, "expected '(' after function name");
    RuParam *params = NULL;
    uint32_t pcap = 0, pcount = 0;

    if (!check(p, TOKEN_RPAREN)) {
        while (1) {
            if (!check(p, TOKEN_IDENT)) {
                fprintf(stderr, "%s:%u:%u: expected parameter name\n",
                        p->lexer.filename, p->cur.pos.line, p->cur.pos.col);
                exit(1);
            }
            char *pname = my_strdup(p->cur.text);
            SourcePos ppos = p->cur.pos;
            parser_advance(p);

            expect(p, TOKEN_COLON, "expected ':' after parameter name");
            RuType *ptype = parse_type(p);

            if (pcount >= pcap) {
                pcap = pcap ? pcap * 2 : 4;
                params = (RuParam *)realloc(params, pcap * sizeof(RuParam));
            }
            params[pcount].name = pname;
            params[pcount].type = ptype;
            params[pcount].pos = ppos;
            pcount++;

            if (!match(p, TOKEN_COMMA)) break;
        }
    }
    expect(p, TOKEN_RPAREN, "expected ')' after parameter list");

    RuType *ret_t = alloc_type(TYPE_VOID);
    if (match(p, TOKEN_ARROW)) {
        ret_t = parse_type(p);
    }

    RuStmt **body = NULL;
    uint32_t stmt_cnt = 0;

    if (is_extern) {
        expect(p, TOKEN_SEMICOLON, "expected ';' for extern fn declaration");
    } else {
        body = parse_block_stmts(p, &stmt_cnt);
    }

    RuFnDef *fndef = (RuFnDef *)calloc(1, sizeof(RuFnDef));
    fndef->name = fn_name;
    fndef->symbol_hash = spark0_hash_str(fn_name);
    fndef->params = params;
    fndef->param_count = pcount;
    fndef->return_type = ret_t;
    fndef->body = body;
    fndef->stmt_count = stmt_cnt;
    fndef->is_extern = is_extern;
    fndef->calling_conv = calling_conv;
    fndef->pos = pos;
    fndef->type_sig_hash = spark0_compute_fn_sig_hash(fndef);

    return fndef;
}

RuModule *spark0_parse(const char *source_text, const char *filename) {
    Parser p;
    memset(&p, 0, sizeof(p));
    lexer_init(&p.lexer, source_text, filename);
    p.cur = lexer_next(&p.lexer);

    RuStructDef **structs = NULL;
    uint32_t s_cap = 0, s_cnt = 0;

    RuFnDef **fns = NULL;
    uint32_t f_cap = 0, f_cnt = 0;

    while (!check(&p, TOKEN_EOF)) {
        uint16_t pending_cconv = 0;
        if (check(&p, TOKEN_HASH)) {
            parser_advance(&p);
            expect(&p, TOKEN_LBRACKET, "expected '[' after '#'");
            if (check(&p, TOKEN_IDENT) && strcmp(p.cur.text, "abi") == 0) {
                parser_advance(&p);
                expect(&p, TOKEN_LPAREN, "expected '(' after 'abi'");
                if (check(&p, TOKEN_STRING_LIT)) {
                    const char *s = p.cur.str_val ? p.cur.str_val : p.cur.text;
                    if (strstr(s, "win64")) pending_cconv = 1;
                    else if (strstr(s, "sysv")) pending_cconv = 0;
                    else if (strstr(s, "eia")) pending_cconv = 2;
                    parser_advance(&p);
                }
                expect(&p, TOKEN_RPAREN, "expected ')' after ABI convention string");
            }
            expect(&p, TOKEN_RBRACKET, "expected ']' after attribute");
        }

        if (check(&p, TOKEN_STRUCT)) {
            if (s_cnt >= s_cap) {
                s_cap = s_cap ? s_cap * 2 : 4;
                structs = (RuStructDef **)realloc(structs, s_cap * sizeof(RuStructDef *));
            }
            structs[s_cnt++] = parse_struct_def(&p);
        } else if (check(&p, TOKEN_EXTERN)) {
            parser_advance(&p);
            if (f_cnt >= f_cap) {
                f_cap = f_cap ? f_cap * 2 : 4;
                fns = (RuFnDef **)realloc(fns, f_cap * sizeof(RuFnDef *));
            }
            fns[f_cnt++] = parse_fn_def(&p, true, pending_cconv);
        } else if (check(&p, TOKEN_FN)) {
            if (f_cnt >= f_cap) {
                f_cap = f_cap ? f_cap * 2 : 4;
                fns = (RuFnDef **)realloc(fns, f_cap * sizeof(RuFnDef *));
            }
            fns[f_cnt++] = parse_fn_def(&p, false, pending_cconv);
        } else {
            fprintf(stderr, "%s:%u:%u: unexpected top-level token: '%s'\n",
                    p.lexer.filename, p.cur.pos.line, p.cur.pos.col,
                    p.cur.text ? p.cur.text : "<unknown>");
            exit(1);
        }
    }

    RuModule *mod = (RuModule *)calloc(1, sizeof(RuModule));
    mod->structs = structs;
    mod->struct_count = s_cnt;
    mod->functions = fns;
    mod->function_count = f_cnt;

    token_free(&p.cur);
    return mod;
}
