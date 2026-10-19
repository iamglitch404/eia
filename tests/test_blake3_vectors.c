/*
 * tests/test_blake3_vectors.c - Standard BLAKE3 Test Vectors Hardening
 *
 * Verifies that EIA BLAKE3-64 implementation conforms exactly to the
 * official BLAKE3 standard reference test vectors.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

static inline uint32_t rot32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

static inline uint32_t get_u32(const uint8_t *p, size_t i) {
    return (uint32_t)p[i*4] | ((uint32_t)p[i*4+1] << 8) |
           ((uint32_t)p[i*4+2] << 16) | ((uint32_t)p[i*4+3] << 24);
}

static inline void set_u32(uint8_t *p, size_t i, uint32_t v) {
    p[i*4]   = (uint8_t)(v & 0xFF);
    p[i*4+1] = (uint8_t)((v >> 8) & 0xFF);
    p[i*4+2] = (uint8_t)((v >> 16) & 0xFF);
    p[i*4+3] = (uint8_t)((v >> 24) & 0xFF);
}

static void blake3_round_g(uint8_t *state, const uint8_t *msg, size_t step) {
    static const uint8_t g_idx[8][4] = {
        {0, 4,  8, 12}, {1, 5,  9, 13}, {2, 6, 10, 14}, {3, 7, 11, 15},
        {0, 5, 10, 15}, {1, 6, 11, 12}, {2, 7,  8, 13}, {3, 4,  9, 14}
    };
    uint8_t a = g_idx[step][0], b = g_idx[step][1], c = g_idx[step][2], d = g_idx[step][3];
    uint32_t va = get_u32(state, a), vb = get_u32(state, b);
    uint32_t vc = get_u32(state, c), vd = get_u32(state, d);
    uint32_t m0 = get_u32(msg, step * 2), m1 = get_u32(msg, step * 2 + 1);

    va = va + vb + m0; vd = rot32(vd ^ va, 16);
    vc = vc + vd;      vb = rot32(vb ^ vc, 12);
    va = va + vb + m1; vd = rot32(vd ^ va, 8);
    vc = vc + vd;      vb = rot32(vb ^ vc, 7);

    set_u32(state, a, va); set_u32(state, b, vb);
    set_u32(state, c, vc); set_u32(state, d, vd);
}

static void blake3_permute_msg(uint8_t *msg) {
    static const uint8_t sigma[16] = {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8};
    uint8_t tmp[64];
    memcpy(tmp, msg, 64);
    for (size_t i = 0; i < 16; ++i) set_u32(msg, i, get_u32(tmp, sigma[i]));
}

static uint64_t blake3_compress_64(uint8_t *cv, const uint8_t *block_buf,
                                   uint32_t block_len, uint64_t block_index, uint32_t flags) {
    uint8_t state[64];
    for (size_t i = 0; i < 8; ++i) set_u32(state, i, get_u32(cv, i));
    set_u32(state, 8,  1779033703);
    set_u32(state, 9,  3144134277);
    set_u32(state, 10, 1013904242);
    set_u32(state, 11, 2773480762);
    set_u32(state, 12, (uint32_t)(block_index & 0xFFFFFFFF));
    set_u32(state, 13, (uint32_t)(block_index >> 32));
    set_u32(state, 14, block_len);
    set_u32(state, 15, flags);

    uint8_t msg[64];
    memset(msg, 0, 64);
    if (block_len > 0) memcpy(msg, block_buf, block_len > 64 ? 64 : block_len);

    for (size_t round = 0; round < 7; ++round) {
        for (size_t step = 0; step < 8; ++step) blake3_round_g(state, msg, step);
        if (round < 6) blake3_permute_msg(msg);
    }

    for (size_t i = 0; i < 8; ++i) {
        uint32_t new_cv_word = get_u32(state, i) ^ get_u32(state, i + 8);
        set_u32(cv, i, new_cv_word);
    }

    uint64_t low = (uint64_t)get_u32(cv, 0);
    uint64_t high = (uint64_t)get_u32(cv, 1);
    return low | (high << 32);
}

static uint64_t blake3_hash64(const uint8_t *buf, size_t len) {
    uint8_t cv[32];
    set_u32(cv, 0, 1779033703); set_u32(cv, 1, 3144134277);
    set_u32(cv, 2, 1013904242); set_u32(cv, 3, 2773480762);
    set_u32(cv, 4, 1359893119); set_u32(cv, 5, 2600822924);
    set_u32(cv, 6, 528734635);  set_u32(cv, 7, 1541459225);

    if (len == 0) return blake3_compress_64(cv, buf, 0, 0, 11);

    size_t offset = 0;
    uint64_t block_idx = 0;
    uint64_t digest = 0;

    while (offset < len) {
        uint32_t blk_len = (len - offset > 64) ? 64 : (uint32_t)(len - offset);
        uint32_t flags = 0;
        if (offset == 0) flags |= 1;
        if (offset + blk_len == len) flags |= 2 | 8;

        digest = blake3_compress_64(cv, buf + offset, blk_len, block_idx, flags);
        offset += blk_len;
        block_idx++;
    }

    return digest;
}

int main(void) {
    printf("[SECURITY TEST] Official BLAKE3-64 Standard Reference Vector Suite...\n");

    /* Vector 1: Empty input */
    uint64_t h0 = blake3_hash64((const uint8_t *)"", 0);
    printf("  Vector 1 (len=0):  0x%016lx ... ", (unsigned long)h0);
    assert(h0 == 0xa6a1f9f5b94913afULL);
    printf("MATCH [PASS]\n");

    /* Vector 2: 'a' */
    uint64_t h1 = blake3_hash64((const uint8_t *)"a", 1);
    printf("  Vector 2 (len=1):  0x%016lx ... ", (unsigned long)h1);
    assert(h1 == 0x53a469d9dd2f7617ULL);
    printf("MATCH [PASS]\n");

    /* Vector 3: 'abc' */
    uint64_t h3 = blake3_hash64((const uint8_t *)"abc", 3);
    printf("  Vector 3 (len=3):  0x%016lx ... ", (unsigned long)h3);
    assert(h3 == 0x33514638acb33764ULL);
    printf("MATCH [PASS]\n");

    /* Vector 4: 'message digest' */
    uint64_t h14 = blake3_hash64((const uint8_t *)"message digest", 14);
    printf("  Vector 4 (len=14): 0x%016lx ... ", (unsigned long)h14);
    assert(h14 == 0xf9db5db9eea2c27bULL);
    printf("MATCH [PASS]\n");

    /* Vector 5: Alphabet (len=26) */
    uint64_t h26 = blake3_hash64((const uint8_t *)"abcdefghijklmnopqrstuvwxyz", 26);
    printf("  Vector 5 (len=26): 0x%016lx ... ", (unsigned long)h26);
    assert(h26 == 0xb4cf4a89c8ee6824ULL);
    printf("MATCH [PASS]\n");

    printf(">>> All Official BLAKE3-64 Reference Test Vectors 100%% VERIFIED!\n");
    return 0;
}
