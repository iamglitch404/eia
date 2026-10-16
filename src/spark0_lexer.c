#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "spark0_lexer.h"

static char *my_strdup(const char *s) {
    size_t l = strlen(s);
    char *d = (char *)malloc(l + 1);
    memcpy(d, s, l + 1);
    return d;
}

void lexer_init(Lexer *l, const char *src, const char *filename) {
    l->src = src;
    l->len = strlen(src);
    l->cursor = 0;
    l->line = 1;
    l->col = 1;
    l->filename = filename;
}

static char peek_char(Lexer *l) {
    if (l->cursor >= l->len) return '\0';
    return l->src[l->cursor];
}

static char peek_char_at(Lexer *l, size_t offset) {
    if (l->cursor + offset >= l->len) return '\0';
    return l->src[l->cursor + offset];
}

static char advance_char(Lexer *l) {
    if (l->cursor >= l->len) return '\0';
    char c = l->src[l->cursor++];
    if (c == '\n') {
        l->line++;
        l->col = 1;
    } else {
        l->col++;
    }
    return c;
}

static void skip_whitespace_and_comments(Lexer *l) {
    while (l->cursor < l->len) {
        char c = peek_char(l);
        if (isspace(c)) {
            advance_char(l);
        } else if (c == '/' && peek_char_at(l, 1) == '/') {
            /* Line comment */
            advance_char(l);
            advance_char(l);
            while (peek_char(l) != '\0' && peek_char(l) != '\n') {
                advance_char(l);
            }
        } else if (c == '/' && peek_char_at(l, 1) == '*') {
            /* Block comment */
            advance_char(l);
            advance_char(l);
            while (peek_char(l) != '\0') {
                if (peek_char(l) == '*' && peek_char_at(l, 1) == '/') {
                    advance_char(l);
                    advance_char(l);
                    break;
                }
                advance_char(l);
            }
        } else {
            break;
        }
    }
}

static char *copy_substr(const char *src, size_t start, size_t len) {
    char *buf = (char *)malloc(len + 1);
    memcpy(buf, src + start, len);
    buf[len] = '\0';
    return buf;
}

Token lexer_next(Lexer *l) {
    skip_whitespace_and_comments(l);

    Token tok;
    memset(&tok, 0, sizeof(tok));
    tok.pos.line = l->line;
    tok.pos.col = l->col;

    if (l->cursor >= l->len) {
        tok.type = TOKEN_EOF;
        tok.text = my_strdup("<EOF>");
        return tok;
    }

    size_t start_pos = l->cursor;
    char c = advance_char(l);

    /* Identifier or keyword */
    if (isalpha(c) || c == '_') {
        while (isalnum(peek_char(l)) || peek_char(l) == '_') {
            advance_char(l);
        }
        size_t id_len = l->cursor - start_pos;
        tok.text = copy_substr(l->src, start_pos, id_len);

        if (strcmp(tok.text, "struct") == 0) tok.type = TOKEN_STRUCT;
        else if (strcmp(tok.text, "fn") == 0) tok.type = TOKEN_FN;
        else if (strcmp(tok.text, "extern") == 0) tok.type = TOKEN_EXTERN;
        else if (strcmp(tok.text, "let") == 0) tok.type = TOKEN_LET;
        else if (strcmp(tok.text, "mut") == 0) tok.type = TOKEN_MUT;
        else if (strcmp(tok.text, "if") == 0) tok.type = TOKEN_IF;
        else if (strcmp(tok.text, "else") == 0) tok.type = TOKEN_ELSE;
        else if (strcmp(tok.text, "while") == 0) tok.type = TOKEN_WHILE;
        else if (strcmp(tok.text, "return") == 0) tok.type = TOKEN_RETURN;
        else if (strcmp(tok.text, "as") == 0) tok.type = TOKEN_AS;
        else if (strcmp(tok.text, "syscall") == 0) tok.type = TOKEN_SYSCALL;
        else if (strcmp(tok.text, "asm") == 0) tok.type = TOKEN_ASM;
        else if (strcmp(tok.text, "i64") == 0) tok.type = TOKEN_TYPE_I64;
        else if (strcmp(tok.text, "u64") == 0) tok.type = TOKEN_TYPE_U64;
        else if (strcmp(tok.text, "i32") == 0) tok.type = TOKEN_TYPE_I32;
        else if (strcmp(tok.text, "u32") == 0) tok.type = TOKEN_TYPE_U32;
        else if (strcmp(tok.text, "u8") == 0) tok.type = TOKEN_TYPE_U8;
        else if (strcmp(tok.text, "void") == 0) tok.type = TOKEN_TYPE_VOID;
        else tok.type = TOKEN_IDENT;

        return tok;
    }

    /* Number literal (hex or decimal) */
    if (isdigit(c)) {
        if (c == '0' && (peek_char(l) == 'x' || peek_char(l) == 'X')) {
            advance_char(l); /* 'x' */
            while (isxdigit(peek_char(l))) {
                advance_char(l);
            }
            tok.type = TOKEN_INT_LIT;
            tok.text = copy_substr(l->src, start_pos, l->cursor - start_pos);
            tok.int_val = strtoull(tok.text, NULL, 16);
            return tok;
        }

        while (isdigit(peek_char(l))) {
            advance_char(l);
        }
        tok.type = TOKEN_INT_LIT;
        tok.text = copy_substr(l->src, start_pos, l->cursor - start_pos);
        tok.int_val = strtoull(tok.text, NULL, 10);
        return tok;
    }

    /* Character literal */
    if (c == '\'') {
        char ch_val = advance_char(l);
        if (ch_val == '\\') {
            char esc = advance_char(l);
            if (esc == 'n') ch_val = '\n';
            else if (esc == 't') ch_val = '\t';
            else if (esc == 'r') ch_val = '\r';
            else if (esc == '0') ch_val = '\0';
            else if (esc == '\'') ch_val = '\'';
            else if (esc == '\\') ch_val = '\\';
        }
        if (peek_char(l) == '\'') {
            advance_char(l); /* closing quote */
        }
        tok.type = TOKEN_CHAR_LIT;
        tok.text = copy_substr(l->src, start_pos, l->cursor - start_pos);
        tok.int_val = (uint8_t)ch_val;
        return tok;
    }

    /* String literal */
    if (c == '"') {
        size_t cap = 64;
        size_t len = 0;
        char *sbuf = (char *)malloc(cap);

        while (peek_char(l) != '"' && peek_char(l) != '\0') {
            char sc = advance_char(l);
            if (sc == '\\') {
                char esc = advance_char(l);
                if (esc == 'n') sc = '\n';
                else if (esc == 't') sc = '\t';
                else if (esc == 'r') sc = '\r';
                else if (esc == '0') sc = '\0';
                else if (esc == '"') sc = '"';
                else if (esc == '\\') sc = '\\';
            }
            if (len + 2 >= cap) {
                cap *= 2;
                sbuf = (char *)realloc(sbuf, cap);
            }
            sbuf[len++] = sc;
        }
        if (peek_char(l) == '"') {
            advance_char(l);
        }
        sbuf[len] = '\0';

        tok.type = TOKEN_STRING_LIT;
        tok.text = copy_substr(l->src, start_pos, l->cursor - start_pos);
        tok.str_val = sbuf;
        tok.str_len = (uint32_t)len;
        return tok;
    }

    /* Punctuation and multi-character operators */
    switch (c) {
        case '-':
            if (peek_char(l) == '>') {
                advance_char(l);
                tok.type = TOKEN_ARROW;
                tok.text = my_strdup("->");
            } else {
                tok.type = TOKEN_MINUS;
                tok.text = my_strdup("-");
            }
            break;
        case '+':
            tok.type = TOKEN_PLUS;
            tok.text = my_strdup("+");
            break;
        case '*':
            tok.type = TOKEN_STAR;
            tok.text = my_strdup("*");
            break;
        case '/':
            tok.type = TOKEN_SLASH;
            tok.text = my_strdup("/");
            break;
        case '%':
            tok.type = TOKEN_PERCENT;
            tok.text = my_strdup("%");
            break;
        case '&':
            if (peek_char(l) == '&') {
                advance_char(l);
                tok.type = TOKEN_AMPAMP;
                tok.text = my_strdup("&&");
            } else {
                tok.type = TOKEN_AMP;
                tok.text = my_strdup("&");
            }
            break;
        case '|':
            if (peek_char(l) == '|') {
                advance_char(l);
                tok.type = TOKEN_PIPEPIPE;
                tok.text = my_strdup("||");
            } else {
                tok.type = TOKEN_PIPE;
                tok.text = my_strdup("|");
            }
            break;
        case '^':
            tok.type = TOKEN_CARET;
            tok.text = my_strdup("^");
            break;
        case '~':
            tok.type = TOKEN_TILDE;
            tok.text = my_strdup("~");
            break;
        case '=':
            if (peek_char(l) == '=') {
                advance_char(l);
                tok.type = TOKEN_EQEQ;
                tok.text = my_strdup("==");
            } else {
                tok.type = TOKEN_EQ;
                tok.text = my_strdup("=");
            }
            break;
        case '!':
            if (peek_char(l) == '=') {
                advance_char(l);
                tok.type = TOKEN_NEQ;
                tok.text = my_strdup("!=");
            } else {
                tok.type = TOKEN_EXCL;
                tok.text = my_strdup("!");
            }
            break;
        case '<':
            if (peek_char(l) == '<') {
                advance_char(l);
                tok.type = TOKEN_SHL;
                tok.text = my_strdup("<<");
            } else if (peek_char(l) == '=') {
                advance_char(l);
                tok.type = TOKEN_LTE;
                tok.text = my_strdup("<=");
            } else {
                tok.type = TOKEN_LT;
                tok.text = my_strdup("<");
            }
            break;
        case '>':
            if (peek_char(l) == '>') {
                advance_char(l);
                tok.type = TOKEN_SHR;
                tok.text = my_strdup(">>");
            } else if (peek_char(l) == '=') {
                advance_char(l);
                tok.type = TOKEN_GTE;
                tok.text = my_strdup(">=");
            } else {
                tok.type = TOKEN_GT;
                tok.text = my_strdup(">");
            }
            break;
        case '.':
            tok.type = TOKEN_DOT;
            tok.text = my_strdup(".");
            break;
        case ',':
            tok.type = TOKEN_COMMA;
            tok.text = my_strdup(",");
            break;
        case ':':
            tok.type = TOKEN_COLON;
            tok.text = my_strdup(":");
            break;
        case ';':
            tok.type = TOKEN_SEMICOLON;
            tok.text = my_strdup(";");
            break;
        case '(':
            tok.type = TOKEN_LPAREN;
            tok.text = my_strdup("(");
            break;
        case ')':
            tok.type = TOKEN_RPAREN;
            tok.text = my_strdup(")");
            break;
        case '{':
            tok.type = TOKEN_LBRACE;
            tok.text = my_strdup("{");
            break;
        case '}':
            tok.type = TOKEN_RBRACE;
            tok.text = my_strdup("}");
            break;
        case '[':
            tok.type = TOKEN_LBRACKET;
            tok.text = my_strdup("[");
            break;
        case ']':
            tok.type = TOKEN_RBRACKET;
            tok.text = my_strdup("]");
            break;
        default:
            tok.type = TOKEN_EOF;
            tok.text = copy_substr(l->src, start_pos, 1);
            break;
    }

    return tok;
}

void token_free(Token *tok) {
    if (tok->text) {
        free(tok->text);
        tok->text = NULL;
    }
    if (tok->str_val) {
        free(tok->str_val);
        tok->str_val = NULL;
    }
}
