/* dogewallet - ChaCha20 (RFC 8439)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Clean-room from RFC 8439, verified against its keystream and AEAD vectors in
 * test/test_aead.c. A stream cipher has no secret-dependent branches, so this is
 * the same low-risk class as the hashes; Poly1305's field arithmetic is the part
 * we vendor instead. */

#include "chacha20.h"
#include "mem.h"

#include <string.h>

static uint32_t rotl(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
static uint32_t rd_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

#define QR(s,a,b,c,d) \
    s[a]+=s[b]; s[d]^=s[a]; s[d]=rotl(s[d],16); \
    s[c]+=s[d]; s[b]^=s[c]; s[b]=rotl(s[b],12); \
    s[a]+=s[b]; s[d]^=s[a]; s[d]=rotl(s[d], 8); \
    s[c]+=s[d]; s[b]^=s[c]; s[b]=rotl(s[b], 7)

void dw_chacha20_block(const uint8_t key[DW_CHACHA20_KEY], uint32_t counter,
                       const uint8_t nonce[DW_CHACHA20_NONCE], uint8_t out[64])
{
    uint32_t s[16], w[16];
    s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) s[4 + i] = rd_le32(key + 4 * i);
    s[12] = counter;
    s[13] = rd_le32(nonce); s[14] = rd_le32(nonce + 4); s[15] = rd_le32(nonce + 8);

    memcpy(w, s, sizeof w);
    for (int i = 0; i < 10; i++) {
        QR(w, 0, 4,  8, 12); QR(w, 1, 5,  9, 13); QR(w, 2, 6, 10, 14); QR(w, 3, 7, 11, 15);
        QR(w, 0, 5, 10, 15); QR(w, 1, 6, 11, 12); QR(w, 2, 7,  8, 13); QR(w, 3, 4,  9, 14);
    }
    for (int i = 0; i < 16; i++) {
        uint32_t v = w[i] + s[i];
        out[4*i] = (uint8_t)v; out[4*i+1] = (uint8_t)(v >> 8);
        out[4*i+2] = (uint8_t)(v >> 16); out[4*i+3] = (uint8_t)(v >> 24);
    }
    dw_secure_zero(w, sizeof w);
    dw_secure_zero(s, sizeof s);
}

void dw_chacha20_xor(const uint8_t key[DW_CHACHA20_KEY], uint32_t counter,
                     const uint8_t nonce[DW_CHACHA20_NONCE],
                     const uint8_t *in, size_t len, uint8_t *out)
{
    uint8_t ks[64];
    size_t off = 0;
    while (off < len) {
        dw_chacha20_block(key, counter, nonce, ks);
        size_t n = len - off < 64 ? len - off : 64;
        for (size_t i = 0; i < n; i++) out[off + i] = in[off + i] ^ ks[i];
        off += n;
        counter++;
    }
    dw_secure_zero(ks, sizeof ks);
}
