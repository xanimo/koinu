/* dogewallet - elliptic curve operations over secp256k1
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

int dw_ec_start(void)
{
    if (g_ctx) return 1;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!ctx) return 0;
    uint8_t seed[32];
    if (!dw_random_bytes(seed, sizeof seed)) { secp256k1_context_destroy(ctx); return 0; }
    int ok = secp256k1_context_randomize(ctx, seed);
    dw_secure_zero(seed, sizeof seed);
    if (!ok) { secp256k1_context_destroy(ctx); return 0; }
    g_ctx = ctx;
    return 1;
}

void dw_ec_stop(void)
{
    if (g_ctx) { secp256k1_context_destroy(g_ctx); g_ctx = NULL; }
}

int dw_ec_seckey_verify(const uint8_t sk[DW_EC_SECKEY_LEN])
{
    if (!g_ctx) return 0;
    return secp256k1_ec_seckey_verify(g_ctx, sk);
}

int dw_ec_pubkey(const uint8_t sk[DW_EC_SECKEY_LEN], uint8_t pub[DW_EC_PUBKEY_LEN])
{
    if (!g_ctx) return 0;
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_create(g_ctx, &pk, sk)) return 0;
    size_t len = DW_EC_PUBKEY_LEN;
    return secp256k1_ec_pubkey_serialize(g_ctx, pub, &len, &pk, SECP256K1_EC_COMPRESSED)
           && len == DW_EC_PUBKEY_LEN;
}

int dw_ec_pubkey_parse(const uint8_t *in, size_t inlen, uint8_t pub[DW_EC_PUBKEY_LEN])
{
    if (!g_ctx) return 0;
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(g_ctx, &pk, in, inlen)) return 0;
    size_t len = DW_EC_PUBKEY_LEN;
    return secp256k1_ec_pubkey_serialize(g_ctx, pub, &len, &pk, SECP256K1_EC_COMPRESSED)
           && len == DW_EC_PUBKEY_LEN;
}

int dw_ec_sign(const uint8_t sk[DW_EC_SECKEY_LEN], const uint8_t hash[32],
               uint8_t sig[DW_EC_SIG_DER_MAX], size_t *siglen)
{
    if (!g_ctx) return 0;
    secp256k1_ecdsa_signature s;
    /* NULL noncefp selects the RFC 6979 default; secp256k1 normalizes to low-S. */
    if (!secp256k1_ecdsa_sign(g_ctx, &s, hash, sk, NULL, NULL)) return 0;
    size_t len = DW_EC_SIG_DER_MAX;
    if (!secp256k1_ecdsa_signature_serialize_der(g_ctx, sig, &len, &s)) return 0;
    *siglen = len;
    return 1;
}

int dw_ec_verify(const uint8_t pub[DW_EC_PUBKEY_LEN], const uint8_t hash[32],
                 const uint8_t *sig, size_t siglen)
{
    if (!g_ctx) return 0;
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(g_ctx, &pk, pub, DW_EC_PUBKEY_LEN)) return 0;
    secp256k1_ecdsa_signature s;
    if (!secp256k1_ecdsa_signature_parse_der(g_ctx, &s, sig, siglen)) return 0;
    return secp256k1_ecdsa_verify(g_ctx, &s, hash, &pk);
}

int dw_ec_seckey_tweak_add(uint8_t sk[DW_EC_SECKEY_LEN], const uint8_t tweak[32])
{
    if (!g_ctx) return 0;
    return secp256k1_ec_seckey_tweak_add(g_ctx, sk, tweak);
}

int dw_ec_pubkey_tweak_add(uint8_t pub[DW_EC_PUBKEY_LEN], const uint8_t tweak[32])
{
    if (!g_ctx) return 0;
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(g_ctx, &pk, pub, DW_EC_PUBKEY_LEN)) return 0;
    if (!secp256k1_ec_pubkey_tweak_add(g_ctx, &pk, tweak)) return 0;
    size_t len = DW_EC_PUBKEY_LEN;
    return secp256k1_ec_pubkey_serialize(g_ctx, pub, &len, &pk, SECP256K1_EC_COMPRESSED)
           && len == DW_EC_PUBKEY_LEN;
}
