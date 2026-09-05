/* dogewallet - ChaCha20-Poly1305 AEAD (RFC 8439)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * The RFC 8439 construction: the Poly1305 one-time key is ChaCha20 block 0,
 * the ciphertext is ChaCha20 from block 1, and the tag is Poly1305 over
 * aad || pad16 || ct || pad16 || le64(aadlen) || le64(ctlen). ChaCha20 is
 * clean-room here; Poly1305 is the vendored poly1305-donna. */

#include "aead.h"
#include "chacha20.h"
#include "mem.h"

#include "poly1305-donna.h"

#include <string.h>

static void le64(uint8_t o[8], uint64_t v)
{
    for (int i = 0; i < 8; i++) o[i] = (uint8_t)(v >> (8 * i));
}

static void tag_compute(const uint8_t key[32], const uint8_t nonce[12],
                        const uint8_t *aad, size_t aadlen,
                        const uint8_t *ct, size_t ctlen,
                        uint8_t tag[16])
{
    uint8_t block0[64], polykey[32];
    dw_chacha20_block(key, 0, nonce, block0);
    memcpy(polykey, block0, 32);

    static const uint8_t zeros[16] = {0};
    poly1305_context ctx;
    poly1305_init(&ctx, polykey);
    poly1305_update(&ctx, aad, aadlen);
    if (aadlen % 16) poly1305_update(&ctx, zeros, 16 - (aadlen % 16));
    poly1305_update(&ctx, ct, ctlen);
    if (ctlen % 16) poly1305_update(&ctx, zeros, 16 - (ctlen % 16));
    uint8_t lens[16];
    le64(lens, aadlen);
    le64(lens + 8, ctlen);
    poly1305_update(&ctx, lens, sizeof lens);
    poly1305_finish(&ctx, tag);

    dw_secure_zero(block0, sizeof block0);
    dw_secure_zero(polykey, sizeof polykey);
}

void dw_chacha20poly1305_encrypt(const uint8_t key[DW_AEAD_KEY],
                                 const uint8_t nonce[DW_AEAD_NONCE],
                                 const uint8_t *aad, size_t aadlen,
                                 const uint8_t *pt, size_t ptlen,
                                 uint8_t *ct, uint8_t tag[DW_AEAD_TAG])
{
    dw_chacha20_xor(key, 1, nonce, pt, ptlen, ct);
    tag_compute(key, nonce, aad, aadlen, ct, ptlen, tag);
}

int dw_chacha20poly1305_decrypt(const uint8_t key[DW_AEAD_KEY],
                                const uint8_t nonce[DW_AEAD_NONCE],
                                const uint8_t *aad, size_t aadlen,
                                const uint8_t *ct, size_t ctlen,
                                const uint8_t tag[DW_AEAD_TAG],
                                uint8_t *pt)
{
    uint8_t want[DW_AEAD_TAG];
    tag_compute(key, nonce, aad, aadlen, ct, ctlen, want);
    if (dw_memeq_ct(want, tag, DW_AEAD_TAG) != 0) {
        dw_secure_zero(want, sizeof want);
        if (pt) dw_secure_zero(pt, ctlen);   /* never expose unauthenticated data */
        return 0;
    }
    dw_secure_zero(want, sizeof want);
    dw_chacha20_xor(key, 1, nonce, ct, ctlen, pt);
    return 1;
}
