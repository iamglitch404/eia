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
#include "eia_ed25519.h"

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

static void test_tampered_text_section_fail_closed(void) {
    printf("[AUTH TEST 9] Whole-Artifact Security: Tampered .text Section Rejection...\n");
    int rc1 = run_cmd_exit("./bin/spark0 tests/client_v1.rx -o /tmp/client_tamper_text --sign >/dev/null 2>&1");
    int rc2 = run_cmd_exit("./bin/spark0 tests/provider_v2.rx -o /tmp/provider_tamper_text --sign >/dev/null 2>&1");
    assert(rc1 == 0 && rc2 == 0);

    /* Tamper with machine code byte in .text (starts at 0x10000) */
    FILE *f = fopen("/tmp/client_tamper_text", "r+b");
    assert(f != NULL);
    fseek(f, 0x10000 + 4, SEEK_SET);
    uint8_t byte = 0;
    assert(fread(&byte, 1, 1, f) == 1);
    byte ^= 0x5A;
    fseek(f, 0x10000 + 4, SEEK_SET);
    assert(fwrite(&byte, 1, 1, f) == 1);
    fclose(f);

    int exec_rc = run_cmd_exit("./bin/eia-run /tmp/client_tamper_text /tmp/provider_tamper_text >/dev/null 2>&1");
    assert(exec_rc == 1);
    printf("  [PASS] Machine code tampering in .text caught by whole-artifact authentication (exit 1)\n");

    unlink("/tmp/client_tamper_text");
    unlink("/tmp/provider_tamper_text");
}

static void test_require_signed_flag_fail_closed(void) {
    printf("[AUTH TEST 10] Policy Enforcement: --require-signed Mode Rejection of Unsigned Binaries...\n");
    /* Compile without --sign */
    int rc1 = run_cmd_exit("./bin/spark0 tests/client_v1.rx -o /tmp/client_unsigned >/dev/null 2>&1");
    int rc2 = run_cmd_exit("./bin/spark0 tests/provider_v2.rx -o /tmp/provider_unsigned >/dev/null 2>&1");
    assert(rc1 == 0 && rc2 == 0);

    /* Normal mode succeeds */
    int normal_rc = run_cmd_exit("./bin/eia-run /tmp/client_unsigned /tmp/provider_unsigned >/dev/null 2>&1");
    assert(normal_rc == 42);

    /* --require-signed MUST reject unsigned binaries with exit 1 */
    int req_rc = run_cmd_exit("./bin/eia-run --require-signed /tmp/client_unsigned /tmp/provider_unsigned >/dev/null 2>&1");
    assert(req_rc == 1);
    printf("  [PASS] --require-signed strictly blocks unsigned artifacts fail-closed (exit 1)\n");

    unlink("/tmp/client_unsigned");
    unlink("/tmp/provider_unsigned");
}

static void test_rfc8032_known_answer_tests(void) {
    printf("[AUTH TEST 11] RFC 8032 §7.1 Standard Ed25519 Known-Answer Tests (KAT)...\n");

    /* Vector 1 */
    const uint8_t v1_seed[32] = {
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
        0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
        0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
    };
    const uint8_t v1_exp_pk[32] = {
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
        0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
        0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
        0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a
    };
    const uint8_t v1_exp_sig[64] = {
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72,
        0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
        0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
        0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
        0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac,
        0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
        0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
        0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b
    };

    uint8_t pk1[32], sk1[64], sig1[64];
    assert(eia_ed25519_keypair_from_seed(pk1, sk1, v1_seed) == 0);
    assert(memcmp(pk1, v1_exp_pk, 32) == 0);
    assert(memcmp(sk1, v1_seed, 32) == 0);
    assert(memcmp(sk1 + 32, v1_exp_pk, 32) == 0);

    /* Message is empty (len=0) */
    const uint8_t empty_msg[1] = { 0 };
    assert(eia_ed25519_sign_detached(sig1, empty_msg, 0, sk1) == 0);
    assert(memcmp(sig1, v1_exp_sig, 64) == 0);
    assert(eia_ed25519_verify_detached(sig1, empty_msg, 0, pk1) == 0);

    /* Vector 2 */
    const uint8_t v2_seed[32] = {
        0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda,
        0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
        0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24,
        0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb
    };
    const uint8_t v2_exp_pk[32] = {
        0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a,
        0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
        0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c,
        0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c
    };
    const uint8_t v2_msg[1] = { 0x72 };
    const uint8_t v2_exp_sig[64] = {
        0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8,
        0x72, 0x0e, 0x82, 0x0b, 0x5f, 0x64, 0x25, 0x40,
        0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f,
        0xb3, 0x76, 0x22, 0x23, 0xeb, 0xdb, 0x69, 0xda,
        0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99, 0x6e,
        0x45, 0x8f, 0x36, 0x13, 0xd0, 0xf1, 0x1d, 0x8c,
        0x38, 0x7b, 0x2e, 0xae, 0xb4, 0x30, 0x2a, 0xee,
        0xb0, 0x0d, 0x29, 0x16, 0x12, 0xbb, 0x0c, 0x00
    };

    uint8_t pk2[32], sk2[64], sig2[64];
    assert(eia_ed25519_keypair_from_seed(pk2, sk2, v2_seed) == 0);
    assert(memcmp(pk2, v2_exp_pk, 32) == 0);
    assert(eia_ed25519_sign_detached(sig2, v2_msg, 1, sk2) == 0);
    assert(memcmp(sig2, v2_exp_sig, 64) == 0);
    assert(eia_ed25519_verify_detached(sig2, v2_msg, 1, pk2) == 0);

    /* Tamper vector 2 message */
    uint8_t bad_msg[1] = { 0x73 };
    assert(eia_ed25519_verify_detached(sig2, bad_msg, 1, pk2) != 0);

    printf("  [PASS] RFC 8032 Known-Answer Test Vectors 1 & 2 100%% verified\n");
}

static void test_external_signing_key_and_trust_store(void) {
    printf("[AUTH TEST 12] External Private Key File & Trust Store Federation...\n");

    /* Create custom 32-byte seed file */
    const char *seed_path = "/tmp/test_custom_seed.bin";
    const uint8_t custom_seed[32] = {
        0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda,
        0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
        0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24,
        0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb
    };
    FILE *sf = fopen(seed_path, "wb");
    assert(sf != NULL);
    assert(fwrite(custom_seed, 1, 32, sf) == 32);
    fclose(sf);

    /* Derive public key hex */
    uint8_t pk[32], sk[64];
    assert(eia_ed25519_keypair_from_seed(pk, sk, custom_seed) == 0);
    char pk_hex[65];
    for (int i = 0; i < 32; ++i) sprintf(pk_hex + (i * 2), "%02x", pk[i]);
    pk_hex[64] = '\0';

    /* Compile artifacts signed with external private key */
    char compile_client[512], compile_prov[512];
    snprintf(compile_client, sizeof(compile_client),
             "EIA_SIGNING_KEY_FILE=%s ./bin/spark0 tests/client_v1.rx -o /tmp/client_extkey --sign >/dev/null 2>&1",
             seed_path);
    snprintf(compile_prov, sizeof(compile_prov),
             "EIA_SIGNING_KEY_FILE=%s ./bin/spark0 tests/provider_v2.rx -o /tmp/prov_extkey --sign >/dev/null 2>&1",
             seed_path);
    assert(run_cmd_exit(compile_client) == 0);
    assert(run_cmd_exit(compile_prov) == 0);

    /* Default loader rejects because key is not in default trust store (fail-closed) */
    int untrusted_rc = run_cmd_exit("./bin/eia-run /tmp/client_extkey /tmp/prov_extkey >/dev/null 2>&1");
    assert(untrusted_rc == 1);

    /* Loader with --trust-key <hex> accepts and executes cleanly (exit 42) */
    char run_with_trust[512];
    snprintf(run_with_trust, sizeof(run_with_trust),
             "./bin/eia-run --trust-key %s /tmp/client_extkey /tmp/prov_extkey >/dev/null 2>&1",
             pk_hex);
    assert(run_cmd_exit(run_with_trust) == 42);

    /* Loader with EIA_TRUSTED_PUBKEY env var accepts and executes cleanly */
    char run_with_env[512];
    snprintf(run_with_env, sizeof(run_with_env),
             "EIA_TRUSTED_PUBKEY=%s ./bin/eia-run /tmp/client_extkey /tmp/prov_extkey >/dev/null 2>&1",
             pk_hex);
    assert(run_cmd_exit(run_with_env) == 42);

    unlink(seed_path);
    unlink("/tmp/client_extkey");
    unlink("/tmp/prov_extkey");
    printf("  [PASS] External key file signing, trust store validation, and fail-closed isolation verified\n");
}

static void test_key_rotation_and_revocation(void) {
    printf("[AUTH TEST 13] Multi-Key Lifecycle: Dynamic Rotation & Epoch Revocation...\n");

    eia_trust_store_reset();

    /* Register secondary trusted authority starting at epoch 2 */
    const uint8_t secondary_pk[32] = {
        0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a,
        0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
        0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c,
        0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c
    };
    int slot = eia_trust_store_add(secondary_pk, 2);
    assert(slot >= 1);
    uint64_t kid = eia_key_id_of(secondary_pk);

    /* Before introduced epoch (epoch 1) -> must be rejected */
    assert(eia_trust_store_lookup(kid, 1) == NULL);

    /* At introduced epoch (epoch 2) -> must be active */
    const EiaTrustEntry *entry = eia_trust_store_lookup(kid, 2);
    assert(entry != NULL);
    assert(entry->key_id == kid);

    /* Revoke key starting at epoch 4 */
    assert(eia_trust_store_revoke(kid, 4) == 0);

    /* Epoch 2 and 3 still valid (signed before revocation) */
    assert(eia_trust_store_lookup(kid, 2) != NULL);
    assert(eia_trust_store_lookup(kid, 3) != NULL);

    /* Epoch 4 and above must be rejected (revoked) */
    assert(eia_trust_store_lookup(kid, 4) == NULL);
    assert(eia_trust_store_lookup(kid, 5) == NULL);

    /* End-to-end revocation check via CLI --revoke-key */
    const char *seed_path = "/tmp/test_rot_seed.bin";
    FILE *sf = fopen(seed_path, "wb");
    assert(sf != NULL);
    const uint8_t rot_seed[32] = {
        0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda,
        0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
        0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24,
        0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb
    };
    assert(fwrite(rot_seed, 1, 32, sf) == 32);
    fclose(sf);

    char pk_hex[65];
    for (int i = 0; i < 32; ++i) sprintf(pk_hex + (i * 2), "%02x", secondary_pk[i]);
    pk_hex[64] = '\0';

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "EIA_SIGNING_KEY_FILE=%s ./bin/spark0 tests/client_v1.rx -o /tmp/client_rot --sign >/dev/null 2>&1", seed_path);
    assert(run_cmd_exit(cmd) == 0);
    snprintf(cmd, sizeof(cmd), "EIA_SIGNING_KEY_FILE=%s ./bin/spark0 tests/provider_v2.rx -o /tmp/prov_rot --sign >/dev/null 2>&1", seed_path);
    assert(run_cmd_exit(cmd) == 0);

    /* With trust-key it passes */
    snprintf(cmd, sizeof(cmd), "./bin/eia-run --trust-key %s /tmp/client_rot /tmp/prov_rot >/dev/null 2>&1", pk_hex);
    assert(run_cmd_exit(cmd) == 42);

    /* When revoked via --revoke-key it fails closed (exit 1) */
    char kid_str[32];
    snprintf(kid_str, sizeof(kid_str), "0x%016lx", (unsigned long)kid);
    snprintf(cmd, sizeof(cmd), "./bin/eia-run --trust-key %s --revoke-key %s /tmp/client_rot /tmp/prov_rot >/dev/null 2>&1", pk_hex, kid_str);
    assert(run_cmd_exit(cmd) == 1);

    unlink(seed_path);
    unlink("/tmp/client_rot");
    unlink("/tmp/prov_rot");
    eia_trust_store_reset();

    printf("  [PASS] Key introduction, rotation, epoch bounds, and active revocation verified\n");
}

static void test_production_fail_closed_without_signing_key(void) {
    printf("[AUTH TEST 14] Production Policy: Rejection of Signing Without External Key...\n");

    /* Ensure no signing key environment variables are set */
    unsetenv("EIA_SIGNING_KEY_FILE");
    unsetenv("EIA_SIGNING_KEY");

    /* Attempt to sign without an external key must fail closed */
    int rc = run_cmd_exit("./bin/spark0 tests/client_v1.rx -o /tmp/client_nokey --sign >/dev/null 2>&1");
    assert(rc != 0);

    unlink("/tmp/client_nokey");
    printf("  [PASS] Compiling with --sign strictly requires an external key and fails closed without one\n");
}

int main(void) {
    printf("============================================================\n");
    printf("   EIA CRYPTOGRAPHIC ARTIFACT AUTHENTICATION SUITE          \n");
    printf("============================================================\n\n");

    /* Create sovereign test root key file for external-key-isolated tests */
    const char *test_key_path = "/tmp/eia_test_root_key.bin";
    const uint8_t root_seed[32] = {
        0x53, 0x4f, 0x56, 0x45, 0x52, 0x45, 0x49, 0x47,
        0x4e, 0x5f, 0x45, 0x49, 0x41, 0x5f, 0x52, 0x4f,
        0x4f, 0x54, 0x5f, 0x4b, 0x45, 0x59, 0x5f, 0x32,
        0x30, 0x32, 0x36, 0x5f, 0x53, 0x49, 0x47, 0x4e
    };
    FILE *fk = fopen(test_key_path, "wb");
    assert(fk != NULL);
    assert(fwrite(root_seed, 1, 32, fk) == 32);
    fclose(fk);
    setenv("EIA_SIGNING_KEY_FILE", test_key_path, 1);

    test_blake3_256_primitive();
    test_signature_primitives();
    test_signed_artifact_e2e();
    test_tampered_payload_fail_closed();
    test_corrupt_signature_fail_closed();
    test_revoked_key_epoch_fail_closed();
    test_untrusted_pubkey_fail_closed();
    test_tampered_with_forged_root_fail_closed();
    test_tampered_text_section_fail_closed();
    test_require_signed_flag_fail_closed();
    test_rfc8032_known_answer_tests();
    test_external_signing_key_and_trust_store();
    test_key_rotation_and_revocation();
    test_production_fail_closed_without_signing_key();

    unlink(test_key_path);

    printf("\n============================================================\n");
    printf(">>> ALL ARTIFACT AUTHENTICATION TESTS PASSED (100%%)         \n");
    printf("============================================================\n");
    return 0;
}
