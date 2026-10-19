/*
 * tests/test_eia_fuzz.c - Hologram & Relocation Parser Robustness & Fuzz Harness
 *
 * Verifies that the EIA parser and loader fail-closed on corrupt, malformed,
 * overflowing, and adversarial inputs without memory safety violations or hangs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include "spark0.h"

static void test_truncated_binaries(void) {
    printf("[FUZZ TEST 1] Truncated Binaries...\n");
    uint8_t tiny[64];
    memset(tiny, 0, sizeof(tiny));

    for (size_t len = 0; len < 64; ++len) {
        char path[] = "/tmp/eia_fuzz_trunc_XXXXXX";
        int fd = mkstemp(path);
        assert(fd >= 0);
        write(fd, tiny, len);
        close(fd);

        char cmd[256];
        snprintf(cmd, sizeof(cmd), "./bin/eia-run %s >/dev/null 2>&1", path);
        int rc = system(cmd);
        unlink(path);
        /* Must reject with non-zero exit code */
        assert(WIFEXITED(rc) && WEXITSTATUS(rc) != 0);
    }
    printf("  All truncated lengths [0..63] rejected cleanly [PASS]\n");
}

static void test_corrupted_headers(void) {
    printf("[FUZZ TEST 2] Corrupted Hologram Headers...\n");
    /* Load valid client_v1 as baseline */
    FILE *f = fopen("bin/client_v1", "rb");
    assert(f != NULL);
    fseek(f, 0, SEEK_END);
    size_t sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = (uint8_t *)malloc(sz);
    assert(fread(buf, 1, sz, f) == sz);
    fclose(f);

    /* 1. Invalid Magic */
    {
        uint8_t *corrupt = (uint8_t *)malloc(sz);
        memcpy(corrupt, buf, sz);
        /* 0x80 is ELF hologram header */
        UniversalHologramHeader *h = (UniversalHologramHeader *)(corrupt + 0x80);
        h->magic = 0xDEADBEEF;

        char path[] = "/tmp/eia_fuzz_magic_XXXXXX";
        int fd = mkstemp(path);
        write(fd, corrupt, sz);
        close(fd);

        char cmd[256];
        snprintf(cmd, sizeof(cmd), "./bin/eia-run %s >/dev/null 2>&1", path);
        int rc = system(cmd);
        unlink(path);
        free(corrupt);
        assert(WIFEXITED(rc) && WEXITSTATUS(rc) != 0);
        printf("  Corrupt magic (0xDEADBEEF) rejected [PASS]\n");
    }

    /* 2. Arithmetic overflow in table offsets */
    {
        uint8_t *corrupt = (uint8_t *)malloc(sz);
        memcpy(corrupt, buf, sz);
        UniversalHologramHeader *h = (UniversalHologramHeader *)(corrupt + 0x80);
        h->contracts_offset = 0xFFFFFFFFFFFFFF00ULL;
        h->contracts_count = 1000;

        char path[] = "/tmp/eia_fuzz_ovf_XXXXXX";
        int fd = mkstemp(path);
        write(fd, corrupt, sz);
        close(fd);

        char cmd[256];
        snprintf(cmd, sizeof(cmd), "./bin/eia-run %s >/dev/null 2>&1", path);
        int rc = system(cmd);
        unlink(path);
        free(corrupt);
        assert(WIFEXITED(rc) && WEXITSTATUS(rc) != 0);
        printf("  Offset overflow (0xFFFFFFFFFFFFFF00) rejected [PASS]\n");
    }

    /* 3. Incompatible ABI epoch */
    {
        uint8_t *corrupt = (uint8_t *)malloc(sz);
        memcpy(corrupt, buf, sz);
        UniversalHologramHeader *h = (UniversalHologramHeader *)(corrupt + 0x80);
        h->abi_epoch = 999; /* Incompatible epoch */

        char path[] = "/tmp/eia_fuzz_epoch_XXXXXX";
        int fd = mkstemp(path);
        write(fd, corrupt, sz);
        close(fd);

        char cmd[256];
        snprintf(cmd, sizeof(cmd), "./bin/eia-run bin/client_v1 %s >/dev/null 2>&1", path);
        int rc = system(cmd);
        unlink(path);
        free(corrupt);
        assert(WIFEXITED(rc) && WEXITSTATUS(rc) != 0);
        printf("  Incompatible ABI epoch (999) rejected [PASS]\n");
    }

    free(buf);
}

int main(void) {
    printf("============================================================\n");
    printf("        EIA HARDENED PARSER & FUZZ ROBUSTNESS SUITE         \n");
    printf("============================================================\n\n");

    test_truncated_binaries();
    test_corrupted_headers();

    printf("\n============================================================\n");
    printf(">>> ALL EIA FUZZ & MALFORMED BINARY TESTS PASSED (100%%)\n");
    printf("============================================================\n");
    return 0;
}
