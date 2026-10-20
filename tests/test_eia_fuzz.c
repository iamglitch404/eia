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

    /* 4. Table count limit overflow (> 65536) */
    {
        uint8_t *corrupt = (uint8_t *)malloc(sz);
        memcpy(corrupt, buf, sz);
        UniversalHologramHeader *h = (UniversalHologramHeader *)(corrupt + 0x80);
        h->contracts_count = 100000;

        char path[] = "/tmp/eia_fuzz_count_XXXXXX";
        int fd = mkstemp(path);
        write(fd, corrupt, sz);
        close(fd);

        char cmd[256];
        snprintf(cmd, sizeof(cmd), "./bin/eia-run %s >/dev/null 2>&1", path);
        int rc = system(cmd);
        unlink(path);
        free(corrupt);
        assert(WIFEXITED(rc) && WEXITSTATUS(rc) != 0);
        printf("  Table limit overflow (100000 > 65536) rejected [PASS]\n");
    }

    free(buf);
}

static void test_excess_providers(void) {
    printf("[FUZZ TEST 3] Excess Provider Count (> 64)...\n");
    char cmd[4096];
    int pos = snprintf(cmd, sizeof(cmd), "./bin/eia-run bin/client_v1");
    for (int i = 0; i < 65; ++i) {
        pos += snprintf(cmd + pos, sizeof(cmd) - pos, " bin/provider_v2");
    }
    snprintf(cmd + pos, sizeof(cmd) - pos, " >/dev/null 2>&1");
    int rc = system(cmd);
    assert(WIFEXITED(rc) && WEXITSTATUS(rc) != 0);
    printf("  Excess providers (65 > 64) rejected cleanly [PASS]\n");
}

static void test_bad_instruction_shape(void) {
    printf("[FUZZ TEST 4] Field Instruction-Shape Corruption...\n");
    FILE *f = fopen("bin/client_v1", "rb");
    assert(f != NULL);
    fseek(f, 0, SEEK_END);
    size_t sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = (uint8_t *)malloc(sz);
    assert(fread(buf, 1, sz, f) == sz);
    fclose(f);

    /* Corrupt the LEA opcode preceding the displacement hole to 0x90 (NOP) */
    const UniversalHologramHeader *h = (const UniversalHologramHeader *)(buf + 0x80);
    const EiaRelocHole *relocs = (const EiaRelocHole *)(buf + h->relocs_offset);
    uint32_t hole_off = relocs[0].insn_offset;
    buf[0x10000 + hole_off - 2] = 0x90; /* NOP opcode */

    char path[] = "/tmp/eia_fuzz_shape_XXXXXX";
    int fd = mkstemp(path);
    write(fd, buf, sz);
    close(fd);

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "./bin/eia-run %s bin/provider_v2 >/dev/null 2>&1", path);
    int rc = system(cmd);
    unlink(path);
    free(buf);
    assert(WIFEXITED(rc) && WEXITSTATUS(rc) != 0);
    printf("  Corrupt field instruction shape (NOP instead of LEA) rejected cleanly [PASS]\n");
}

static void test_universal_container_fuzz(void) {
    printf("[FUZZ TEST 5] Universal Container ('UEIA') Hardened Rejection...\n");

    /* Compile valid universal artifact as baseline */
    int comp_rc = system("./bin/spark0 tests/hello_eia.rx -o /tmp/base_univ.eia --target=universal >/dev/null 2>&1");
    assert(comp_rc == 0);

    FILE *f = fopen("/tmp/base_univ.eia", "rb");
    assert(f != NULL);
    fseek(f, 0, SEEK_END);
    size_t sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = (uint8_t *)malloc(sz);
    assert(fread(buf, 1, sz, f) == sz);
    fclose(f);

    /* 1. Incompatible Universal Version */
    {
        uint8_t *corrupt = (uint8_t *)malloc(sz);
        memcpy(corrupt, buf, sz);
        EiaUniversalHeader *uh = (EiaUniversalHeader *)corrupt;
        uh->version_major = 99;

        char path[] = "/tmp/eia_fuzz_uver_XXXXXX";
        int fd = mkstemp(path);
        write(fd, corrupt, sz);
        close(fd);

        char cmd[256];
        snprintf(cmd, sizeof(cmd), "./bin/eia-run %s >/dev/null 2>&1", path);
        int rc = system(cmd);
        unlink(path);
        free(corrupt);
        assert(WIFEXITED(rc) && WEXITSTATUS(rc) != 0);
        printf("  Incompatible Universal Version (v99.0) rejected [PASS]\n");
    }

    /* 2. Slice Count Overflow (> EIA_MAX_SLICES) */
    {
        uint8_t *corrupt = (uint8_t *)malloc(sz);
        memcpy(corrupt, buf, sz);
        EiaUniversalHeader *uh = (EiaUniversalHeader *)corrupt;
        uh->slice_count = 100;

        char path[] = "/tmp/eia_fuzz_uslice_XXXXXX";
        int fd = mkstemp(path);
        write(fd, corrupt, sz);
        close(fd);

        char cmd[256];
        snprintf(cmd, sizeof(cmd), "./bin/eia-run %s >/dev/null 2>&1", path);
        int rc = system(cmd);
        unlink(path);
        free(corrupt);
        assert(WIFEXITED(rc) && WEXITSTATUS(rc) != 0);
        printf("  Slice Count Overflow (100 > 8) rejected [PASS]\n");
    }

    /* 3. Slice Offset Out-of-Bounds */
    {
        uint8_t *corrupt = (uint8_t *)malloc(sz);
        memcpy(corrupt, buf, sz);
        EiaUniversalSliceHeader *sl = (EiaUniversalSliceHeader *)(corrupt + sizeof(EiaUniversalHeader));
        sl[0].slice_offset = 0xFFFFFFFF0000ULL;

        char path[] = "/tmp/eia_fuzz_uoff_XXXXXX";
        int fd = mkstemp(path);
        write(fd, corrupt, sz);
        close(fd);

        char cmd[256];
        snprintf(cmd, sizeof(cmd), "./bin/eia-run %s >/dev/null 2>&1", path);
        int rc = system(cmd);
        unlink(path);
        free(corrupt);
        assert(WIFEXITED(rc) && WEXITSTATUS(rc) != 0);
        printf("  Out-of-bounds slice offset rejected [PASS]\n");
    }

    /* 4. Overlapping Slices */
    {
        uint8_t *corrupt = (uint8_t *)malloc(sz);
        memcpy(corrupt, buf, sz);
        EiaUniversalSliceHeader *sl = (EiaUniversalSliceHeader *)(corrupt + sizeof(EiaUniversalHeader));
        /* Force slice 1 to overlap slice 0 */
        sl[1].slice_offset = sl[0].slice_offset + 100;
        sl[1].slice_size = 0x50000;

        char path[] = "/tmp/eia_fuzz_uovlp_XXXXXX";
        int fd = mkstemp(path);
        write(fd, corrupt, sz);
        close(fd);

        char cmd[256];
        snprintf(cmd, sizeof(cmd), "./bin/eia-run %s >/dev/null 2>&1", path);
        int rc = system(cmd);
        unlink(path);
        free(corrupt);
        assert(WIFEXITED(rc) && WEXITSTATUS(rc) != 0);
        printf("  Overlapping slice ranges rejected safely [PASS]\n");
    }

    free(buf);
    unlink("/tmp/base_univ.eia");
}

int main(void) {
    printf("============================================================\n");
    printf("        EIA HARDENED PARSER & FUZZ ROBUSTNESS SUITE         \n");
    printf("============================================================\n\n");

    test_truncated_binaries();
    test_corrupted_headers();
    test_excess_providers();
    test_bad_instruction_shape();
    test_universal_container_fuzz();

    printf("\n============================================================\n");
    printf(">>> ALL EIA FUZZ & MALFORMED BINARY TESTS PASSED (100%%)\n");
    printf("============================================================\n");
    return 0;
}
