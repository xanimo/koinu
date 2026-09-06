/* koinu.dog - HMAC over SHA-256 and SHA-512 (RFC 2104)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * H(k xor opad || H(k xor ipad || msg)), with a key longer than the block first
 * hashed down. Verified against the RFC 4231 vectors in test/test_hmac.c. */

#include "hmac.h"
#include "mem.h"

#include <string.h>

void kw_hmac_sha256(const uint8_t *key, size_t keylen,
                    const uint8_t *msg, size_t msglen,
                    uint8_t out[KW_SHA256_LEN])
{
    uint8_t k0[KW_SHA256_BLOCK];
    memset(k0, 0, sizeof k0);
    if (keylen > KW_SHA256_BLOCK) kw_sha256(key, keylen, k0);
    else                          memcpy(k0, key, keylen);

    uint8_t ipad[KW_SHA256_BLOCK], opad[KW_SHA256_BLOCK];
    for (size_t i = 0; i < KW_SHA256_BLOCK; i++) {
        ipad[i] = k0[i] ^ 0x36;
        opad[i] = k0[i] ^ 0x5c;
    }

    uint8_t inner[KW_SHA256_LEN];
    kw_sha256_ctx c;
    kw_sha256_init(&c);
    kw_sha256_update(&c, ipad, sizeof ipad);
    kw_sha256_update(&c, msg, msglen);
    kw_sha256_final(&c, inner);

    kw_sha256_init(&c);
    kw_sha256_update(&c, opad, sizeof opad);
    kw_sha256_update(&c, inner, sizeof inner);
    kw_sha256_final(&c, out);

    kw_secure_zero(k0, sizeof k0);
    kw_secure_zero(ipad, sizeof ipad);
    kw_secure_zero(opad, sizeof opad);
    kw_secure_zero(inner, sizeof inner);
}

void kw_hmac_sha512(const uint8_t *key, size_t keylen,
                    const uint8_t *msg, size_t msglen,
                    uint8_t out[KW_SHA512_LEN])
{
    uint8_t k0[KW_SHA512_BLOCK];
    memset(k0, 0, sizeof k0);
    if (keylen > KW_SHA512_BLOCK) kw_sha512(key, keylen, k0);
    else                          memcpy(k0, key, keylen);

    uint8_t ipad[KW_SHA512_BLOCK], opad[KW_SHA512_BLOCK];
    for (size_t i = 0; i < KW_SHA512_BLOCK; i++) {
        ipad[i] = k0[i] ^ 0x36;
        opad[i] = k0[i] ^ 0x5c;
    }

    uint8_t inner[KW_SHA512_LEN];
    kw_sha512_ctx c;
    kw_sha512_init(&c);
    kw_sha512_update(&c, ipad, sizeof ipad);
    kw_sha512_update(&c, msg, msglen);
    kw_sha512_final(&c, inner);

    kw_sha512_init(&c);
    kw_sha512_update(&c, opad, sizeof opad);
    kw_sha512_update(&c, inner, sizeof inner);
    kw_sha512_final(&c, out);

    kw_secure_zero(k0, sizeof k0);
    kw_secure_zero(ipad, sizeof ipad);
    kw_secure_zero(opad, sizeof opad);
    kw_secure_zero(inner, sizeof inner);
}
