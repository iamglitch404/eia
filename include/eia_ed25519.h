#ifndef EIA_ED25519_H
#define EIA_ED25519_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * EIA Ed25519 Asymmetric Cryptographic Engine
 * RFC 8032 / TweetNaCl standard Ed25519 signature algorithm.
 */

int  eia_ed25519_keypair_from_seed(uint8_t pk[32], uint8_t sk[64], const uint8_t seed[32]);
int  eia_ed25519_sign_detached(uint8_t sig[64], const uint8_t *msg, size_t msg_len, const uint8_t sk[64]);
int  eia_ed25519_verify_detached(const uint8_t sig[64], const uint8_t *msg, size_t msg_len, const uint8_t pk[32]);

void eia_sign_digest(const uint8_t digest[32], uint16_t key_epoch, uint8_t out_sig[64]);
bool eia_verify_digest(const uint8_t digest[32], uint16_t key_epoch, uint64_t pubkey_id, const uint8_t sig[64]);

#ifdef __cplusplus
}
#endif

#endif /* EIA_ED25519_H */
