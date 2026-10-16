#ifndef SPARK0_LEXER_H
#define SPARK0_LEXER_H

#include "../include/spark0.h"

typedef struct {
    TokenType type;
    SourcePos pos;
    char     *text;
    uint64_t  int_val;
    char     *str_val;
    uint32_t  str_len;
} Token;

typedef struct {
    const char *src;
    size_t      len;
    size_t      cursor;
    uint32_t    line;
    uint32_t    col;
    const char *filename;
} Lexer;

void lexer_init(Lexer *l, const char *src, const char *filename);
Token lexer_next(Lexer *l);
void token_free(Token *tok);

#endif /* SPARK0_LEXER_H */
