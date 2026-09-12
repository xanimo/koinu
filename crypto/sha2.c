/* koinu.dog - SHA-256 and SHA-512 (FIPS 180-4)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Clean-room from FIPS 180-4, verified against the standard known-answer tests
 * in test/test_sha2.c. A hash has no secret-dependent branches, so this is the
 * one class of primitive where a spec implementation checked against vectors
 * carries none of the risk that rolling an AEAD or KDF would. */

#include "sha2.h"
#include "mem.h"

#include <string.h>

static uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
static uint64_t rotr64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

/* ── SHA-256 ─────────────────────────────────────────────────── */

const uint32_t kw_sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static const uint32_t SHA256_IV[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

void kw_sha256_init(kw_sha256_ctx *c)
{
    memcpy(c->h, SHA256_IV, sizeof c->h);
    c->bits = 0;
    c->n = 0;
}

/* One round, with the working variables passed by name so the caller rotates them
   at compile time. Written out eight at a time below: rolled, the compiler emits the
   a-through-h shuffle every round, which is most of what a round costs. */
#define SHA256_R(a, b, c, d, e, f, g, h, k, w) do {                       \
    uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);           \
    uint32_t ch = (e & f) ^ (~e & g);                                     \
    uint32_t t1 = (h) + S1 + ch + (k) + (w);                              \
    uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);           \
    uint32_t mj = ((a) & (b)) ^ ((a) & (c)) ^ ((b) & (c));                \
    (d) += t1;                                                            \
    (h) = t1 + S0 + mj;                                                   \
} while (0)

/* The schedule as a sixteen-word window rather than a sixty-four word array: each
   word is only read by the fifteen rounds after it, so the rest is dead weight and
   sixteen words of secret to wipe instead of sixty-four. */
#define SHA256_W(i) (w[(i) & 15] +=                                                \
    (rotr32(w[((i) - 15) & 15], 7) ^ rotr32(w[((i) - 15) & 15], 18) ^              \
     (w[((i) - 15) & 15] >> 3)) + w[((i) - 7) & 15] +                              \
    (rotr32(w[((i) - 2) & 15], 17) ^ rotr32(w[((i) - 2) & 15], 19) ^               \
     (w[((i) - 2) & 15] >> 10)))

#define SHA256_EIGHT(i, W0, W1, W2, W3, W4, W5, W6, W7) do {              \
    SHA256_R(a, b, cc, d, e, f, g, hh, kw_sha256_k[(i) + 0], W0);                \
    SHA256_R(hh, a, b, cc, d, e, f, g, kw_sha256_k[(i) + 1], W1);                \
    SHA256_R(g, hh, a, b, cc, d, e, f, kw_sha256_k[(i) + 2], W2);                \
    SHA256_R(f, g, hh, a, b, cc, d, e, kw_sha256_k[(i) + 3], W3);                \
    SHA256_R(e, f, g, hh, a, b, cc, d, kw_sha256_k[(i) + 4], W4);                \
    SHA256_R(d, e, f, g, hh, a, b, cc, kw_sha256_k[(i) + 5], W5);                \
    SHA256_R(cc, d, e, f, g, hh, a, b, kw_sha256_k[(i) + 6], W6);                \
    SHA256_R(b, cc, d, e, f, g, hh, a, kw_sha256_k[(i) + 7], W7);                \
} while (0)

void kw_sha256_compress_scalar(uint32_t h[8], const uint8_t *p)
{
    uint32_t w[16];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)p[i*4] << 24 | (uint32_t)p[i*4+1] << 16 |
               (uint32_t)p[i*4+2] << 8 | (uint32_t)p[i*4+3];

    uint32_t a = h[0], b = h[1], cc = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];

    SHA256_EIGHT(0,  w[0],  w[1],  w[2],  w[3],  w[4],  w[5],  w[6],  w[7]);
    SHA256_EIGHT(8,  w[8],  w[9],  w[10], w[11], w[12], w[13], w[14], w[15]);
    for (int i = 16; i < 64; i += 8)
        SHA256_EIGHT(i, SHA256_W(i + 0), SHA256_W(i + 1), SHA256_W(i + 2), SHA256_W(i + 3),
                        SHA256_W(i + 4), SHA256_W(i + 5), SHA256_W(i + 6), SHA256_W(i + 7));

    h[0] += a; h[1] += b; h[2] += cc; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g;  h[7] += hh;
    kw_secure_zero(w, sizeof w);
}

/* One test for the hardware core per call is a predictable branch against several
   hundred cycles of hashing, so it is not worth caching here. */
void kw_sha256_compress(uint32_t h[8], const uint8_t *p)
{
    if (kw_sha256_hw()) kw_sha256_compress_hw(h, p);
    else                kw_sha256_compress_scalar(h, p);
}

static void sha256_block(kw_sha256_ctx *c, const uint8_t *p)
{
    kw_sha256_compress(c->h, p);
}

void kw_sha256_update(kw_sha256_ctx *c, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    c->bits += (uint64_t)len * 8;
    if (c->n) {
        size_t take = KW_SHA256_BLOCK - c->n;
        if (take > len) take = len;
        memcpy(c->buf + c->n, p, take);
        c->n += take; p += take; len -= take;
        if (c->n == KW_SHA256_BLOCK) { sha256_block(c, c->buf); c->n = 0; }
    }
    while (len >= KW_SHA256_BLOCK) { sha256_block(c, p); p += KW_SHA256_BLOCK; len -= KW_SHA256_BLOCK; }
    if (len) { memcpy(c->buf, p, len); c->n = len; }
}

void kw_sha256_final(kw_sha256_ctx *c, uint8_t out[KW_SHA256_LEN])
{
    uint64_t bits = c->bits;
    uint8_t pad = 0x80;
    kw_sha256_update(c, &pad, 1);
    uint8_t zero = 0;
    while (c->n != 56) kw_sha256_update(c, &zero, 1);
    uint8_t lenbe[8];
    for (int i = 0; i < 8; i++) lenbe[i] = (uint8_t)(bits >> (56 - 8*i));
    kw_sha256_update(c, lenbe, 8);
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(c->h[i] >> 24);
        out[i*4+1] = (uint8_t)(c->h[i] >> 16);
        out[i*4+2] = (uint8_t)(c->h[i] >> 8);
        out[i*4+3] = (uint8_t)(c->h[i]);
    }
    kw_secure_zero(c, sizeof *c);
}

void kw_sha256(const void *data, size_t len, uint8_t out[KW_SHA256_LEN])
{
    kw_sha256_ctx c;
    kw_sha256_init(&c);
    kw_sha256_update(&c, data, len);
    kw_sha256_final(&c, out);
}

/* Pad (len) bytes into (blocks) and return how many 64-byte blocks that is. Only
   for lengths that fit two blocks, which is every double hash on the hot paths: an
   80-byte header, a 64-byte merkle node, a 32-byte digest. */
static size_t pad_short(uint8_t *blocks, const void *data, size_t len)
{
    size_t nb = len <= 55 ? 1 : 2;
    size_t total = nb * KW_SHA256_BLOCK;
    if (len) memcpy(blocks, data, len);   /* memcpy from NULL is undefined even at zero */
    blocks[len] = 0x80;
    memset(blocks + len + 1, 0, total - len - 1);
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) blocks[total - 1 - i] = (uint8_t)(bits >> (8 * i));
    return nb;
}

/* Two hashes, without going round the streaming path twice for them. At these
   lengths the context setup, the copy into its buffer, the padding and the wipe cost
   about as much as the compressions do, and a block header is hashed six million
   times in a sync. */
void kw_hash256(const void *data, size_t len, uint8_t out[KW_SHA256_LEN])
{
    uint8_t blocks[2 * KW_SHA256_BLOCK];
    uint32_t h[8];

    if (len > 119) {                       /* long enough that the padding is not the cost */
        uint8_t t[KW_SHA256_LEN];
        kw_sha256(data, len, t);
        kw_sha256(t, sizeof t, out);
        kw_secure_zero(t, sizeof t);
        return;
    }

    size_t nb = pad_short(blocks, data, len);
    memcpy(h, SHA256_IV, sizeof h);
    kw_sha256_compress(h, blocks);
    if (nb == 2) kw_sha256_compress(h, blocks + KW_SHA256_BLOCK);

    /* the digest of the first hash, big-endian, is the second hash's only 32 bytes */
    uint8_t inner[KW_SHA256_LEN];
    for (int i = 0; i < 8; i++) {
        inner[i*4]     = (uint8_t)(h[i] >> 24);
        inner[i*4 + 1] = (uint8_t)(h[i] >> 16);
        inner[i*4 + 2] = (uint8_t)(h[i] >> 8);
        inner[i*4 + 3] = (uint8_t)h[i];
    }
    pad_short(blocks, inner, sizeof inner);
    memcpy(h, SHA256_IV, sizeof h);
    kw_sha256_compress(h, blocks);
    for (int i = 0; i < 8; i++) {
        out[i*4]     = (uint8_t)(h[i] >> 24);
        out[i*4 + 1] = (uint8_t)(h[i] >> 16);
        out[i*4 + 2] = (uint8_t)(h[i] >> 8);
        out[i*4 + 3] = (uint8_t)h[i];
    }
    kw_secure_zero(blocks, sizeof blocks);
    kw_secure_zero(h, sizeof h);
    kw_secure_zero(inner, sizeof inner);
}

/* ── SHA-512 ─────────────────────────────────────────────────── */

static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

void kw_sha512_init(kw_sha512_ctx *c)
{
    c->h[0] = 0x6a09e667f3bcc908ULL; c->h[1] = 0xbb67ae8584caa73bULL;
    c->h[2] = 0x3c6ef372fe94f82bULL; c->h[3] = 0xa54ff53a5f1d36f1ULL;
    c->h[4] = 0x510e527fade682d1ULL; c->h[5] = 0x9b05688c2b3e6c1fULL;
    c->h[6] = 0x1f83d9abfb41bd6bULL; c->h[7] = 0x5be0cd19137e2179ULL;
    c->bits_hi = c->bits_lo = 0;
    c->n = 0;
}

static void sha512_block(kw_sha512_ctx *c, const uint8_t *p)
{
    uint64_t w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = 0;
        for (int j = 0; j < 8; j++) w[i] = (w[i] << 8) | p[i*8 + j];
    }
    for (int i = 16; i < 80; i++) {
        uint64_t s0 = rotr64(w[i-15], 1) ^ rotr64(w[i-15], 8) ^ (w[i-15] >> 7);
        uint64_t s1 = rotr64(w[i-2], 19) ^ rotr64(w[i-2], 61) ^ (w[i-2] >> 6);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint64_t a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3];
    uint64_t e = c->h[4], f = c->h[5], g = c->h[6], hh = c->h[7];
    for (int i = 0; i < 80; i++) {
        uint64_t S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
        uint64_t ch = (e & f) ^ (~e & g);
        uint64_t t1 = hh + S1 + ch + K512[i] + w[i];
        uint64_t S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
        uint64_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        uint64_t t2 = S0 + maj;
        hh = g; g = f; f = e; e = d + t1; d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
    c->h[4] += e; c->h[5] += f; c->h[6] += g;  c->h[7] += hh;
    kw_secure_zero(w, sizeof w);
}

void kw_sha512_update(kw_sha512_ctx *c, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    uint64_t add = (uint64_t)len * 8;
    if ((c->bits_lo += add) < add) c->bits_hi++;
    if (c->n) {
        size_t take = KW_SHA512_BLOCK - c->n;
        if (take > len) take = len;
        memcpy(c->buf + c->n, p, take);
        c->n += take; p += take; len -= take;
        if (c->n == KW_SHA512_BLOCK) { sha512_block(c, c->buf); c->n = 0; }
    }
    while (len >= KW_SHA512_BLOCK) { sha512_block(c, p); p += KW_SHA512_BLOCK; len -= KW_SHA512_BLOCK; }
    if (len) { memcpy(c->buf, p, len); c->n = len; }
}

void kw_sha512_final(kw_sha512_ctx *c, uint8_t out[KW_SHA512_LEN])
{
    uint64_t hi = c->bits_hi, lo = c->bits_lo;
    uint8_t pad = 0x80;
    kw_sha512_update(c, &pad, 1);
    uint8_t zero = 0;
    while (c->n != 112) kw_sha512_update(c, &zero, 1);
    uint8_t lenbe[16];
    for (int i = 0; i < 8; i++) lenbe[i]   = (uint8_t)(hi >> (56 - 8*i));
    for (int i = 0; i < 8; i++) lenbe[8+i] = (uint8_t)(lo >> (56 - 8*i));
    kw_sha512_update(c, lenbe, 16);
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++)
            out[i*8 + j] = (uint8_t)(c->h[i] >> (56 - 8*j));
    kw_secure_zero(c, sizeof *c);
}

void kw_sha512(const void *data, size_t len, uint8_t out[KW_SHA512_LEN])
{
    kw_sha512_ctx c;
    kw_sha512_init(&c);
    kw_sha512_update(&c, data, len);
    kw_sha512_final(&c, out);
}
