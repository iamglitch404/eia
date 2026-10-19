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

/* --- Core primitives ---------------------------------------------------- */
int  eia_ed25519_keypair_from_seed(uint8_t pk[32], uint8_t sk[64], const uint8_t seed[32]);
int  eia_ed25519_sign_detached(uint8_t sig[64], const uint8_t *msg, size_t msg_len, const uint8_t sk[64]);
int  eia_ed25519_verify_detached(const uint8_t sig[64], const uint8_t *msg, size_t msg_len, const uint8_t pk[32]);

/* --- High-level artifact digest sign/verify ----------------------------- */
int  eia_sign_digest(const uint8_t digest[32], uint16_t key_epoch, uint8_t out_sig[64]);
bool eia_verify_digest(const uint8_t digest[32], uint16_t key_epoch, uint64_t pubkey_id, const uint8_t sig[64]);

/* --- Production trust store (multi-key, rotation, revocation) ----------- */
#define EIA_KEYSTORE_MAX          8
#define EIA_KEYSTORE_FLAG_ACTIVE  0x01u
#define EIA_KEYSTORE_FLAG_REVOKED 0x02u

typedef struct {
    uint64_t key_id;           /* FNV-1a 64-bit hash of the public key bytes */
    uint8_t  pubkey[32];       /* Ed25519 public key                          */
    uint16_t introduced_epoch; /* First ABI epoch this key is valid from      */
    uint16_t revoked_epoch;    /* Epoch at which revocation takes effect (0=never) */
    uint8_t  flags;            /* EIA_KEYSTORE_FLAG_* bitmask                 */
} EiaTrustEntry;

/*
 * eia_trust_store_add  – register a new trusted public key.
 *   Returns slot index (0..EIA_KEYSTORE_MAX-1) or -1 if the store is full.
 */
int eia_trust_store_add(const uint8_t pk[32], uint16_t introduced_epoch);

/*
 * eia_trust_store_revoke – revoke a key by key_id.
 *   The key is rejected for all artifacts signed at key_epoch >= revoked_epoch.
 *   Returns 0 on success, -1 if key_id was not found.
 */
int eia_trust_store_revoke(uint64_t key_id, uint16_t revoked_epoch);

/*
 * eia_trust_store_lookup – find a non-revoked entry for the given key_id and
 *   epoch.  Returns NULL if absent, revoked, or not yet introduced.
 */
const EiaTrustEntry *eia_trust_store_lookup(uint64_t key_id, uint16_t for_epoch);

/* Reset trust store to initial state (root key only) */
void eia_trust_store_reset(void);

/* Derive 64-bit FNV-1a key ID from 32-byte public key */
uint64_t eia_key_id_of(const uint8_t pk[32]);

/* Derive active signing public key ID and epoch from configured seed/env */
uint64_t eia_get_active_signing_key_id(uint16_t *out_epoch, uint8_t out_pk[32]);

#ifdef __cplusplus
}
#endif

#endif /* EIA_ED25519_H */
