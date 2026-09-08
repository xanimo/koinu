/* koinu.dog - elliptic curve operations over secp256k1
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "ec.h"
#include "rng.h"
#include "mem.h"

#include <secp256k1.h>

/* One randomized context for the process. secp256k1's own docs note a context
   can both sign and verify; we randomize it so key-dependent branches are
   blinded. */
static secp256k1_context *g_ctx = NULL;

int kw_ec_start(void)
{
    if (g_ctx) return 1;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!ctx) return 0;
    uint8_t seed[32];
    if (!kw_random_bytes(seed, sizeof seed)) { secp256k1_context_destroy(ctx); return 0; }
    int ok = secp256k1_context_randomize(ctx, seed);
    kw_secure_zero(seed, sizeof seed);
    if (!ok) { secp256k1_context_destroy(ctx); return 0; }
    g_ctx = ctx;
    return 1;
}

void kw_ec_stop(void)
{
    if (g_ctx) { secp256k1_context_destroy(g_ctx); g_ctx = NULL; }
}

int kw_ec_seckey_verify(const uint8_t sk[KW_EC_SECKEY_LEN])
{
    if (!g_ctx) return 0;
    return secp256k1_ec_seckey_verify(g_ctx, sk);
}

int kw_ec_pubkey(const uint8_t sk[KW_EC_SECKEY_LEN], uint8_t pub[KW_EC_PUBKEY_LEN])
{
    if (!g_ctx) return 0;
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_create(g_ctx, &pk, sk)) return 0;
    size_t len = KW_EC_PUBKEY_LEN;
    return secp256k1_ec_pubkey_serialize(g_ctx, pub, &len, &pk, SECP256K1_EC_COMPRESSED)
           && len == KW_EC_PUBKEY_LEN;
}

int kw_ec_pubkey_uncompressed(const uint8_t sk[KW_EC_SECKEY_LEN], uint8_t pub[65])
{
    if (!g_ctx) return 0;
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_create(g_ctx, &pk, sk)) return 0;
    size_t len = 65;
    return secp256k1_ec_pubkey_serialize(g_ctx, pub, &len, &pk, SECP256K1_EC_UNCOMPRESSED)
           && len == 65;
}

int kw_ec_pubkey_parse(const uint8_t *in, size_t inlen, uint8_t pub[KW_EC_PUBKEY_LEN])
{
    if (!g_ctx) return 0;
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(g_ctx, &pk, in, inlen)) return 0;
    size_t len = KW_EC_PUBKEY_LEN;
    return secp256k1_ec_pubkey_serialize(g_ctx, pub, &len, &pk, SECP256K1_EC_COMPRESSED)
           && len == KW_EC_PUBKEY_LEN;
}

int kw_ec_sign(const uint8_t sk[KW_EC_SECKEY_LEN], const uint8_t hash[32],
               uint8_t sig[KW_EC_SIG_DER_MAX], size_t *siglen)
{
    if (!g_ctx) return 0;
    secp256k1_ecdsa_signature s;
    /* NULL noncefp selects the RFC 6979 default; secp256k1 normalizes to low-S. */
    if (!secp256k1_ecdsa_sign(g_ctx, &s, hash, sk, NULL, NULL)) return 0;
    size_t len = KW_EC_SIG_DER_MAX;
    if (!secp256k1_ecdsa_signature_serialize_der(g_ctx, sig, &len, &s)) return 0;
    *siglen = len;
    return 1;
}

int kw_ec_verify(const uint8_t pub[KW_EC_PUBKEY_LEN], const uint8_t hash[32],
                 const uint8_t *sig, size_t siglen)
{
    if (!g_ctx) return 0;
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(g_ctx, &pk, pub, KW_EC_PUBKEY_LEN)) return 0;
    secp256k1_ecdsa_signature s;
    if (!secp256k1_ecdsa_signature_parse_der(g_ctx, &s, sig, siglen)) return 0;
    return secp256k1_ecdsa_verify(g_ctx, &s, hash, &pk);
}

int kw_ec_seckey_tweak_add(uint8_t sk[KW_EC_SECKEY_LEN], const uint8_t tweak[32])
{
    if (!g_ctx) return 0;
    return secp256k1_ec_seckey_tweak_add(g_ctx, sk, tweak);
}

int kw_ec_pubkey_tweak_add(uint8_t pub[KW_EC_PUBKEY_LEN], const uint8_t tweak[32])
{
    if (!g_ctx) return 0;
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(g_ctx, &pk, pub, KW_EC_PUBKEY_LEN)) return 0;
    if (!secp256k1_ec_pubkey_tweak_add(g_ctx, &pk, tweak)) return 0;
    size_t len = KW_EC_PUBKEY_LEN;
    return secp256k1_ec_pubkey_serialize(g_ctx, pub, &len, &pk, SECP256K1_EC_COMPRESSED)
           && len == KW_EC_PUBKEY_LEN;
}
