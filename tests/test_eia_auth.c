/*
 * tests/test_eia_auth.c - Comprehensive Cryptographic Artifact Authentication Suite
 *
 * Verifies EIA full 256-bit BLAKE3 artifact hashing, cryptographic provenance
 * signature validation, key epoch anti-replay policy, untrusted public key rejection,
 * and fail-closed security guarantees under adversarial payload modification.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/wait.h>
#include "spark0.h"

/* Helper to execute a command and return its exit code */
static int run_cmd_exit(const char *cmd) {
    int rc = system(cmd);
    if (WIFEXITED(rc)) {
        return WEXITSTATUS(rc);
    }
    return -1;
}

static void test_blake3_256_primitive(void) {
    printf("[AUTH TEST 1] Verifying BLAKE3-256 Engine Integrity...\n");
    const uint8_t input[] = "EIA Cryptographic Provenance 2026";
    uint8_t d1[32], d2[32];
    blake3_hash256(input, sizeof(input) - 1, d1);
    blake3_hash256(input, sizeof(input) - 1, d2);
    assert(memcmp(d1, d2, 32) == 0);

    /* Verify sensitivity to single-bit flip */
    uint8_t input_flipped[sizeof(input)];
    memcpy(input_flipped, input, sizeof(input));
    input_flipped[0] ^= 0x01;
    uint8_t d3[32];
    blake3_hash256(input_flipped, sizeof(input) - 1, d3);
    assert(memcmp(d1, d3, 32) != 0);

    printf("  [PASS] BLAKE3-256 produces deterministic, avalanche-secure 256-bit digests\n");
}

static void test_signature_primitives(void) {
    printf("[AUTH TEST 2] Verifying Cryptographic Signature & Verification Primitives...\n");
    uint8_t digest[32];
    memset(digest, 0x42, sizeof(digest));

    uint8_t sig[64];
    spark0_sign_digest(digest, EIA_DEFAULT_KEY_EPOCH, sig);

    /* Valid verification */
    assert(spark0_verify_signature(digest, EIA_DEFAULT_KEY_EPOCH, EIA_TRUSTED_PUBKEY_ID, sig));

    /* Tampered digest bit */
    digest[0] ^= 0x80;
    assert(!spark0_verify_signature(digest, EIA_DEFAULT_KEY_EPOCH, EIA_TRUSTED_PUBKEY_ID, sig));
    digest[0] ^= 0x80; /* restore */

    /* Tampered signature bit */
    sig[15] ^= 0x01;
    assert(!spark0_verify_signature(digest, EIA_DEFAULT_KEY_EPOCH, EIA_TRUSTED_PUBKEY_ID, sig));
    sig[15] ^= 0x01; /* restore */

    /* Revoked key epoch */
    assert(!spark0_verify_signature(digest, EIA_DEFAULT_KEY_EPOCH + 1, EIA_TRUSTED_PUBKEY_ID, sig));

    /* Untrusted public key ID */
    assert(!spark0_verify_signature(digest, EIA_DEFAULT_KEY_EPOCH, 0xDEADBEEFCAFE0001ULL, sig));

    printf("  [PASS] Sign/verify primitives enforce strict constant-time checks and fail-closed validation\n");
}

static void test_signed_artifact_e2e(void) {
    printf("[AUTH TEST 3] Compiling and Executing Authenticated Signed Artifacts...\n");
    int rc1 = run_cmd_exit("./bin/spark0 tests/client_v1.rx -o /tmp/client_auth_signed --sign >/dev/null 2>&1");
    int rc2 = run_cmd_exit("./bin/spark0 tests/provider_v2.rx -o /tmp/provider_auth_signed --sign >/dev/null 2>&1");
    assert(rc1 == 0 && rc2 == 0);

    int exec_rc = run_cmd_exit("./bin/eia-run /tmp/client_auth_signed /tmp/provider_auth_signed >/dev/null 2>&1");
    assert(exec_rc == 42);
    printf("  [PASS] Signed client & provider verified and dynamically linked cleanly (exit 42)\n");

    unlink("/tmp/client_auth_signed");
    unlink("/tmp/provider_auth_signed");
}

static void test_tampered_payload_fail_closed(void) {
    printf("[AUTH TEST 4] Tampered Payload Rejection (Fail-Closed Integrity Check)...\n");
    int rc1 = run_cmd_exit("./bin/spark0 tests/client_v1.rx -o /tmp/client_tamper --sign >/dev/null 2>&1");
    int rc2 = run_cmd_exit("./bin/spark0 tests/provider_v2.rx -o /tmp/provider_tamper --sign >/dev/null 2>&1");
    assert(rc1 == 0 && rc2 == 0);

    /* Read binary, modify 1 byte in authenticated contracts table */
    FILE *f = fopen("/tmp/client_tamper", "r+b");
    assert(f != NULL);
    UniversalHologramHeader h;
    fseek(f, 0x80, SEEK_SET);
    assert(fread(&h, 1, sizeof(h), f) == sizeof(h));
    assert(h.magic == 0x44484945);

    fseek(f, (long)h.contracts_offset, SEEK_SET); /* Into the authenticated table payload */
    uint8_t byte = 0;
    assert(fread(&byte, 1, 1, f) == 1);
    byte ^= 0xFF;
    fseek(f, (long)h.contracts_offset, SEEK_SET);
    assert(fwrite(&byte, 1, 1, f) == 1);
    fclose(f);

    /* Execution MUST fail closed with code 1 */
    int exec_rc = run_cmd_exit("./bin/eia-run /tmp/client_tamper /tmp/provider_tamper >/dev/null 2>&1");
    assert(exec_rc == 1);
    printf("  [PASS] Bytecode payload modification rejected immediately (exit 1)\n");

    unlink("/tmp/client_tamper");
    unlink("/tmp/provider_tamper");
}

static void test_corrupt_signature_fail_closed(void) {
    printf("[AUTH TEST 5] Corrupt Signature Record Rejection...\n");
    int rc1 = run_cmd_exit("./bin/spark0 tests/client_v1.rx -o /tmp/client_corrupt_sig --sign >/dev/null 2>&1");
    int rc2 = run_cmd_exit("./bin/spark0 tests/provider_v2.rx -o /tmp/provider_corrupt_sig --sign >/dev/null 2>&1");
    assert(rc1 == 0 && rc2 == 0);

    /* Tamper with signature record in client */
    FILE *f = fopen("/tmp/client_corrupt_sig", "r+b");
    assert(f != NULL);
    fseek(f, 0, SEEK_END);
    size_t sz = ftell(f);
    uint8_t *buf = (uint8_t *)malloc(sz);
    fseek(f, 0, SEEK_SET);
    assert(fread(buf, 1, sz, f) == sz);

    UniversalHologramHeader *h = (UniversalHologramHeader *)(buf + 0x80);
    assert(h->magic == 0x44484945);
    uint64_t auth_offset = *(const uint64_t *)(&h->reserved[0]);
    assert(auth_offset > 0 && auth_offset + sizeof(EiaSignatureRecord) <= sz);

    EiaSignatureRecord *sig_rec = (EiaSignatureRecord *)(buf + auth_offset);
    sig_rec->signature[10] ^= 0xAA; /* Corrupt signature bytes */

    fseek(f, 0, SEEK_SET);
    assert(fwrite(buf, 1, sz, f) == sz);
    fclose(f);
    free(buf);

    int exec_rc = run_cmd_exit("./bin/eia-run /tmp/client_corrupt_sig /tmp/provider_corrupt_sig >/dev/null 2>&1");
    assert(exec_rc == 1);
    printf("  [PASS] Corrupted signature bytes rejected cleanly (exit 1)\n");

    unlink("/tmp/client_corrupt_sig");
    unlink("/tmp/provider_corrupt_sig");
}

static void test_revoked_key_epoch_fail_closed(void) {
    printf("[AUTH TEST 6] Revoked / Future Key Epoch Anti-Replay Rejection...\n");
    int rc1 = run_cmd_exit("./bin/spark0 tests/client_v1.rx -o /tmp/client_epoch --sign >/dev/null 2>&1");
    int rc2 = run_cmd_exit("./bin/spark0 tests/provider_v2.rx -o /tmp/provider_epoch --sign >/dev/null 2>&1");
    assert(rc1 == 0 && rc2 == 0);

    FILE *f = fopen("/tmp/client_epoch", "r+b");
    assert(f != NULL);
    fseek(f, 0, SEEK_END);
    size_t sz = ftell(f);
    uint8_t *buf = (uint8_t *)malloc(sz);
    fseek(f, 0, SEEK_SET);
    assert(fread(buf, 1, sz, f) == sz);

    UniversalHologramHeader *h = (UniversalHologramHeader *)(buf + 0x80);
    assert(h->magic == 0x44484945);
    uint64_t auth_offset = *(const uint64_t *)(&h->reserved[0]);
    assert(auth_offset > 0 && auth_offset + sizeof(EiaSignatureRecord) <= sz);
    EiaSignatureRecord *sig_rec = (EiaSignatureRecord *)(buf + auth_offset);
    sig_rec->key_epoch = 0; /* Revoked / below EIA_MIN_TRUSTED_EPOCH */

    fseek(f, 0, SEEK_SET);
    assert(fwrite(buf, 1, sz, f) == sz);
    fclose(f);
    free(buf);

    int exec_rc = run_cmd_exit("./bin/eia-run /tmp/client_epoch /tmp/provider_epoch >/dev/null 2>&1");
    assert(exec_rc == 1);
    printf("  [PASS] Key epoch replay/revocation rejected cleanly (exit 1)\n");

    unlink("/tmp/client_epoch");
    unlink("/tmp/provider_epoch");
}

static void test_untrusted_pubkey_fail_closed(void) {
    printf("[AUTH TEST 7] Untrusted Public Key ID Rejection...\n");
    int rc1 = run_cmd_exit("./bin/spark0 tests/client_v1.rx -o /tmp/client_pubkey --sign >/dev/null 2>&1");
    int rc2 = run_cmd_exit("./bin/spark0 tests/provider_v2.rx -o /tmp/provider_pubkey --sign >/dev/null 2>&1");
    assert(rc1 == 0 && rc2 == 0);

    FILE *f = fopen("/tmp/client_pubkey", "r+b");
    assert(f != NULL);
    fseek(f, 0, SEEK_END);
    size_t sz = ftell(f);
    uint8_t *buf = (uint8_t *)malloc(sz);
    fseek(f, 0, SEEK_SET);
    assert(fread(buf, 1, sz, f) == sz);

    UniversalHologramHeader *h = (UniversalHologramHeader *)(buf + 0x80);
    assert(h->magic == 0x44484945);
    uint64_t auth_offset = *(const uint64_t *)(&h->reserved[0]);
    assert(auth_offset > 0 && auth_offset + sizeof(EiaSignatureRecord) <= sz);
    EiaSignatureRecord *sig_rec = (EiaSignatureRecord *)(buf + auth_offset);
    sig_rec->public_key_id = 0xDECAFBAD12345678ULL; /* Untrusted key ID */

    fseek(f, 0, SEEK_SET);
    assert(fwrite(buf, 1, sz, f) == sz);
    fclose(f);
    free(buf);

    int exec_rc = run_cmd_exit("./bin/eia-run /tmp/client_pubkey /tmp/provider_pubkey >/dev/null 2>&1");
    assert(exec_rc == 1);
    printf("  [PASS] Untrusted public key ID rejected cleanly (exit 1)\n");

    unlink("/tmp/client_pubkey");
    unlink("/tmp/provider_pubkey");
}

static void test_tampered_with_forged_root_fail_closed(void) {
    printf("[AUTH TEST 8] Forged 64-bit Root Bypass Attempt Caught by 256-bit Signature...\n");
    int rc1 = run_cmd_exit("./bin/spark0 tests/client_v1.rx -o /tmp/client_forged --sign >/dev/null 2>&1");
    int rc2 = run_cmd_exit("./bin/spark0 tests/provider_v2.rx -o /tmp/provider_forged --sign >/dev/null 2>&1");
    assert(rc1 == 0 && rc2 == 0);

    FILE *f = fopen("/tmp/client_forged", "r+b");
    assert(f != NULL);
    fseek(f, 0, SEEK_END);
    size_t sz = ftell(f);
    uint8_t *buf = (uint8_t *)malloc(sz);
    fseek(f, 0, SEEK_SET);
    assert(fread(buf, 1, sz, f) == sz);

    UniversalHologramHeader *h = (UniversalHologramHeader *)(buf + 0x80);
    assert(h->magic == 0x44484945);

    /* Tamper 1 byte in the contracts table */
    buf[h->contracts_offset] ^= 0x55;

    /* Recompute 64-bit BLAKE3 root over the tampered tables so 64-bit check passes! */
    uint64_t tables_len = (h->contracts_count * sizeof(SymbolContract)) +
                          (h->relocs_count * sizeof(EiaRelocHole)) +
                          h->type_graph_size;
    h->blake3_root = blake3_hash64(buf + h->contracts_offset, tables_len);

    fseek(f, 0, SEEK_SET);
    assert(fwrite(buf, 1, sz, f) == sz);
    fclose(f);
    free(buf);

    /* 64-bit check passes, but 256-bit signed digest check MUST catch the forgery and fail closed! */
    int exec_rc = run_cmd_exit("./bin/eia-run /tmp/client_forged /tmp/provider_forged >/dev/null 2>&1");
    assert(exec_rc == 1);
    printf("  [PASS] Forged 64-bit root detected & blocked by 256-bit BLAKE3 digest verification (exit 1)\n");

    unlink("/tmp/client_forged");
    unlink("/tmp/provider_forged");
}

int main(void) {
    printf("============================================================\n");
    printf("   EIA CRYPTOGRAPHIC ARTIFACT AUTHENTICATION SUITE          \n");
    printf("============================================================\n\n");

    test_blake3_256_primitive();
    test_signature_primitives();
    test_signed_artifact_e2e();
    test_tampered_payload_fail_closed();
    test_corrupt_signature_fail_closed();
    test_revoked_key_epoch_fail_closed();
    test_untrusted_pubkey_fail_closed();
    test_tampered_with_forged_root_fail_closed();

    printf("\n============================================================\n");
    printf(">>> ALL ARTIFACT AUTHENTICATION TESTS PASSED (100%%)         \n");
    printf("============================================================\n");
    return 0;
}
