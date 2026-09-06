/* koinu.dog - RIPEMD-160
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Clean-room from the Dobbertin/Bosselaers/Preneel specification, verified
 * against its published test vectors in test/test_ripemd160.c. Little-endian
 * throughout: message words, the length suffix, and the digest, unlike SHA-2. */

#include "ripemd160.h"
#include "sha2.h"
#include "mem.h"

#include <string.h>

static uint32_t rol(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

static uint32_t f(int j, uint32_t x, uint32_t y, uint32_t z)
{
    if (j < 16) return x ^ y ^ z;
    if (j < 32) return (x & y) | (~x & z);
    if (j < 48) return (x | ~y) ^ z;
    if (j < 64) return (x & z) | (y & ~z);
    return x ^ (y | ~z);
}

/* message word order, left and right lines */
static const uint8_t RL[80] = {
     0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
     7, 4,13, 1,10, 6,15, 3,12, 0, 9, 5, 2,14,11, 8,
     3,10,14, 4, 9,15, 8, 1, 2, 7, 0, 6,13,11, 5,12,
     1, 9,11,10, 0, 8,12, 4,13, 3, 7,15,14, 5, 6, 2,
     4, 0, 5, 9, 7,12, 2,10,14, 1, 3, 8,11, 6,15,13
};
static const uint8_t RR[80] = {
     5,14, 7, 0, 9, 2,11, 4,13, 6,15, 8, 1,10, 3,12,
     6,11, 3, 7, 0,13, 5,10,14,15, 8,12, 4, 9, 1, 2,
    15, 5, 1, 3, 7,14, 6, 9,11, 8,12, 2,10, 0, 4,13,
     8, 6, 4, 1, 3,11,15, 0, 5,12, 2,13, 9, 7,10,14,
    12,15,10, 4, 1, 5, 8, 7, 6, 2,13,14, 0, 3, 9,11
};
/* rotate amounts, left and right lines */
static const uint8_t SL[80] = {
    11,14,15,12, 5, 8, 7, 9,11,13,14,15, 6, 7, 9, 8,
     7, 6, 8,13,11, 9, 7,15, 7,12,15, 9,11, 7,13,12,
    11,13, 6, 7,14, 9,13,15,14, 8,13, 6, 5,12, 7, 5,
    11,12,14,15,14,15, 9, 8, 9,14, 5, 6, 8, 6, 5,12,
     9,15, 5,11, 6, 8,13,12, 5,12,13,14,11, 8, 5, 6
};
static const uint8_t SR[80] = {
     8, 9, 9,11,13,15,15, 5, 7, 7, 8,11,14,14,12, 6,
     9,13,15, 7,12, 8, 9,11, 7, 7,12, 7, 6,15,13,11,
     9, 7,15,11, 8, 6, 6,14,12,13, 5,14,13,13, 7, 5,
    15, 5, 8,11,14,14, 6,14, 6, 9,12, 9,12, 5,15, 8,
     8, 5,12, 9,12, 5,14, 6, 8,13, 6, 5,15,13,11,11
};
static const uint32_t KL[5] = { 0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e };
static const uint32_t KR[5] = { 0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000 };

void kw_ripemd160_init(kw_ripemd160_ctx *c)
{
    c->h[0] = 0x67452301; c->h[1] = 0xefcdab89; c->h[2] = 0x98badcfe;
    c->h[3] = 0x10325476; c->h[4] = 0xc3d2e1f0;
    c->bits = 0;
    c->n = 0;
}

static void ripemd160_block(kw_ripemd160_ctx *c, const uint8_t *p)
{
    uint32_t x[16];
    for (int i = 0; i < 16; i++)
        x[i] = (uint32_t)p[i*4] | (uint32_t)p[i*4+1] << 8 |
               (uint32_t)p[i*4+2] << 16 | (uint32_t)p[i*4+3] << 24;

    uint32_t al = c->h[0], bl = c->h[1], cl = c->h[2], dl = c->h[3], el = c->h[4];
    uint32_t ar = c->h[0], br = c->h[1], cr = c->h[2], dr = c->h[3], er = c->h[4];

    for (int j = 0; j < 80; j++) {
        uint32_t t = rol(al + f(j, bl, cl, dl) + x[RL[j]] + KL[j/16], SL[j]) + el;
        al = el; el = dl; dl = rol(cl, 10); cl = bl; bl = t;

        t = rol(ar + f(79 - j, br, cr, dr) + x[RR[j]] + KR[j/16], SR[j]) + er;
        ar = er; er = dr; dr = rol(cr, 10); cr = br; br = t;
    }

    uint32_t t = c->h[1] + cl + dr;
    c->h[1] = c->h[2] + dl + er;
    c->h[2] = c->h[3] + el + ar;
    c->h[3] = c->h[4] + al + br;
    c->h[4] = c->h[0] + bl + cr;
    c->h[0] = t;

    kw_secure_zero(x, sizeof x);
}

void kw_ripemd160_update(kw_ripemd160_ctx *c, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    c->bits += (uint64_t)len * 8;
    if (c->n) {
        size_t take = KW_RIPEMD160_BLOCK - c->n;
        if (take > len) take = len;
        memcpy(c->buf + c->n, p, take);
        c->n += take; p += take; len -= take;
        if (c->n == KW_RIPEMD160_BLOCK) { ripemd160_block(c, c->buf); c->n = 0; }
    }
    while (len >= KW_RIPEMD160_BLOCK) { ripemd160_block(c, p); p += KW_RIPEMD160_BLOCK; len -= KW_RIPEMD160_BLOCK; }
    if (len) { memcpy(c->buf, p, len); c->n = len; }
}

void kw_ripemd160_final(kw_ripemd160_ctx *c, uint8_t out[KW_RIPEMD160_LEN])
{
    uint64_t bits = c->bits;
    uint8_t pad = 0x80;
    kw_ripemd160_update(c, &pad, 1);
    uint8_t zero = 0;
    while (c->n != 56) kw_ripemd160_update(c, &zero, 1);
    uint8_t lenle[8];
    for (int i = 0; i < 8; i++) lenle[i] = (uint8_t)(bits >> (8 * i));  /* little-endian */
    kw_ripemd160_update(c, lenle, 8);
    for (int i = 0; i < 5; i++) {
        out[i*4]   = (uint8_t)(c->h[i]);
        out[i*4+1] = (uint8_t)(c->h[i] >> 8);
        out[i*4+2] = (uint8_t)(c->h[i] >> 16);
        out[i*4+3] = (uint8_t)(c->h[i] >> 24);
    }
    kw_secure_zero(c, sizeof *c);
}

void kw_ripemd160(const void *data, size_t len, uint8_t out[KW_RIPEMD160_LEN])
{
    kw_ripemd160_ctx c;
    kw_ripemd160_init(&c);
    kw_ripemd160_update(&c, data, len);
    kw_ripemd160_final(&c, out);
}

void kw_hash160(const void *data, size_t len, uint8_t out[KW_RIPEMD160_LEN])
{
    uint8_t sha[KW_SHA256_LEN];
    kw_sha256(data, len, sha);
    kw_ripemd160(sha, sizeof sha, out);
    kw_secure_zero(sha, sizeof sha);
}
