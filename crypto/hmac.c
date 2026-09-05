/* dogewallet - HMAC over SHA-256 and SHA-512 (RFC 2104)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * H(k xor opad || H(k xor ipad || msg)), with a key longer than the block first
 * hashed down. Verified against the RFC 4231 vectors in test/test_hmac.c. */

#include "hmac.h"
#include "mem.h"

#include <string.h>

void dw_hmac_sha256(const uint8_t *key, size_t keylen,
                    const uint8_t *msg, size_t msglen,
                    uint8_t out[DW_SHA256_LEN])
{
    uint8_t k0[DW_SHA256_BLOCK];
    memset(k0, 0, sizeof k0);
    if (keylen > DW_SHA256_BLOCK) dw_sha256(key, keylen, k0);
    else                          memcpy(k0, key, keylen);

    uint8_t ipad[DW_SHA256_BLOCK], opad[DW_SHA256_BLOCK];
    for (size_t i = 0; i < DW_SHA256_BLOCK; i++) {
        ipad[i] = k0[i] ^ 0x36;
        opad[i] = k0[i] ^ 0x5c;
    }

    uint8_t inner[DW_SHA256_LEN];
    dw_sha256_ctx c;
    dw_sha256_init(&c);
    dw_sha256_update(&c, ipad, sizeof ipad);
    dw_sha256_update(&c, msg, msglen);
    dw_sha256_final(&c, inner);

    dw_sha256_init(&c);
    dw_sha256_update(&c, opad, sizeof opad);
    dw_sha256_update(&c, inner, sizeof inner);
    dw_sha256_final(&c, out);

    dw_secure_zero(k0, sizeof k0);
    dw_secure_zero(ipad, sizeof ipad);
    dw_secure_zero(opad, sizeof opad);
    dw_secure_zero(inner, sizeof inner);
}

void dw_hmac_sha512(const uint8_t *key, size_t keylen,
                    const uint8_t *msg, size_t msglen,
                    uint8_t out[DW_SHA512_LEN])
{
    uint8_t k0[DW_SHA512_BLOCK];
    memset(k0, 0, sizeof k0);
    if (keylen > DW_SHA512_BLOCK) dw_sha512(key, keylen, k0);
    else                          memcpy(k0, key, keylen);

    uint8_t ipad[DW_SHA512_BLOCK], opad[DW_SHA512_BLOCK];
    for (size_t i = 0; i < DW_SHA512_BLOCK; i++) {
        ipad[i] = k0[i] ^ 0x36;
        opad[i] = k0[i] ^ 0x5c;
    }

    uint8_t inner[DW_SHA512_LEN];
    dw_sha512_ctx c;
    dw_sha512_init(&c);
    dw_sha512_update(&c, ipad, sizeof ipad);
    dw_sha512_update(&c, msg, msglen);
    dw_sha512_final(&c, inner);

    dw_sha512_init(&c);
    dw_sha512_update(&c, opad, sizeof opad);
    dw_sha512_update(&c, inner, sizeof inner);
    dw_sha512_final(&c, out);

    dw_secure_zero(k0, sizeof k0);
    dw_secure_zero(ipad, sizeof ipad);
    dw_secure_zero(opad, sizeof opad);
    dw_secure_zero(inner, sizeof inner);
}
