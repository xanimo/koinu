/* koinu.dog - elliptic curve operations over secp256k1
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * A thin, opinionated wrapper: compressed pubkeys only, deterministic (RFC 6979)
 * low-S signatures, and the two tweak-adds BIP32 child derivation needs. The
 * heavy lifting is secp256k1's; this fixes the encodings and the failure mode. */

#ifndef KOINU_EC_H
#define KOINU_EC_H

#include <stddef.h>
#include <stdint.h>

#define KW_EC_SECKEY_LEN   32
#define KW_EC_PUBKEY_LEN   33     /* compressed */
#define KW_EC_SIG_DER_MAX  72     /* longest DER-encoded ECDSA signature */

/* Create and randomize the module context. Returns 1 on success, 0 on failure
   (including a failed RNG draw), in which case nothing else here may be called.
   Randomizing the context blinds it against side-channel leakage of the key. */
int  kw_ec_start(void);
void kw_ec_stop(void);

/* 1 if (sk) is a valid secret key (in range, non-zero). */
int  kw_ec_seckey_verify(const uint8_t sk[KW_EC_SECKEY_LEN]);

/* Compressed public key for (sk). Returns 1 on success. */
int  kw_ec_pubkey(const uint8_t sk[KW_EC_SECKEY_LEN], uint8_t pub[KW_EC_PUBKEY_LEN]);

/* Parse and validate a public key of any standard encoding, re-emitting it
   compressed. Rejects points not on the curve. Returns 1 on success. */
int  kw_ec_pubkey_parse(const uint8_t *in, size_t inlen, uint8_t pub[KW_EC_PUBKEY_LEN]);

/* Deterministic (RFC 6979), low-S ECDSA signature over the 32-byte (hash),
   DER-encoded into (sig) with its length in (siglen). Returns 1 on success. */
int  kw_ec_sign(const uint8_t sk[KW_EC_SECKEY_LEN], const uint8_t hash[32],
                uint8_t sig[KW_EC_SIG_DER_MAX], size_t *siglen);

/* 1 if the DER signature verifies for (pub) over (hash). Strict DER and low-S
   are required, matching what a default node's mempool will accept. */
int  kw_ec_verify(const uint8_t pub[KW_EC_PUBKEY_LEN], const uint8_t hash[32],
                  const uint8_t *sig, size_t siglen);

/* BIP32 derivation. Add (tweak) to a secret key or the matching public key,
   in place. Return 1 on success; 0 means the tweak produced an invalid key and
   the caller must skip to the next index, per BIP32. */
int  kw_ec_seckey_tweak_add(uint8_t sk[KW_EC_SECKEY_LEN], const uint8_t tweak[32]);
int  kw_ec_pubkey_tweak_add(uint8_t pub[KW_EC_PUBKEY_LEN], const uint8_t tweak[32]);

#endif /* KOINU_EC_H */
