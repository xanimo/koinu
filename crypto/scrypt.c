/* koinu.dog - scrypt (RFC 7914)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * scrypt is PBKDF2 to fill a buffer, ROMix over it, then PBKDF2 again to
 * squeeze the answer out. ROMix is the part that costs: it writes N blocks of
 * 128*r bytes into a scratchpad, then makes N passes that each read one block
 * back at an index derived from the data, so the work cannot be done without
 * the memory. At Dogecoin's N=1024, r=1 that is a 128KB scratchpad and 4096
 * Salsa20/8 invocations per header: two per BlockMix, one BlockMix per
 * iteration, 2N iterations.
 *
 * Salsa20/8 is therefore the only hot function. It is written three times: an
 * SSE2 form, a NEON form, and a portable one. The SIMD forms keep the state in
 * the shuffled column-major layout Percival's reference uses, so the shuffle is
 * paid once on entry and once on exit rather than every round.
 *
 * Verified against the RFC 7914 vectors and, at Dogecoin's parameters, against
 * OpenSSL, in test/test_scrypt.c. */

#include "scrypt.h"
#include "pbkdf2.h"
#include "mem.h"

#include <stdlib.h>
#include <string.h>

/* -DKW_SCRYPT_PORTABLE forces the scalar core, so a test can hold the SIMD ones
   against it on any machine. */
#if defined(KW_SCRYPT_PORTABLE)
#  define KW_SCRYPT_BACKEND "portable"
#elif defined(__SSE2__)
#  include <emmintrin.h>
#  define KW_SCRYPT_BACKEND "sse2"
#elif defined(__ARM_NEON) || defined(__ARM_NEON__)
#  include <arm_neon.h>
#  define KW_SCRYPT_BACKEND "neon"
#else
#  define KW_SCRYPT_BACKEND "portable"
#endif

const char *kw_scrypt_backend(void) { return KW_SCRYPT_BACKEND; }

static inline uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

/* ── Salsa20/8 ───────────────────────────────────────────────────────────
   The core operates on 16 words. B is both input and output, and the result is
   the round function's output added to its input, as Salsa20 specifies. */

#if defined(__SSE2__) && !defined(KW_SCRYPT_PORTABLE)

/* Each register holds one position of all four quarter-rounds, so one vector
   operation does four. The column round's quarter-rounds are (0,4,8,12),
   (5,9,13,1), (10,14,2,6) and (15,3,7,11), which fixes the lanes:
     x0 = { 0,  5, 10, 15}   x1 = { 4,  9, 14,  3}
     x2 = { 8, 13,  2,  7}   x3 = {12,  1,  6, 11}
   The row round needs {0,1,2,3}, {5,6,7,4}, {10,11,8,9}, {15,12,13,14}, which
   is the same four registers rotated, and rotated back afterwards. */
#define ROTL_EPI32(v, c) _mm_or_si128(_mm_slli_epi32((v), (c)), _mm_srli_epi32((v), 32 - (c)))

#define QR_SSE(a, b, cc, d) \
    t = _mm_add_epi32(a, d);  b  = _mm_xor_si128(b,  ROTL_EPI32(t, 7));  \
    t = _mm_add_epi32(b, a);  cc = _mm_xor_si128(cc, ROTL_EPI32(t, 9));  \
    t = _mm_add_epi32(cc, b); d  = _mm_xor_si128(d,  ROTL_EPI32(t, 13)); \
    t = _mm_add_epi32(d, cc); a  = _mm_xor_si128(a,  ROTL_EPI32(t, 18));

static void salsa20_8(uint32_t B[16])
{
    __m128i x0 = _mm_set_epi32((int)B[15], (int)B[10], (int)B[5],  (int)B[0]);
    __m128i x1 = _mm_set_epi32((int)B[3],  (int)B[14], (int)B[9],  (int)B[4]);
    __m128i x2 = _mm_set_epi32((int)B[7],  (int)B[2],  (int)B[13], (int)B[8]);
    __m128i x3 = _mm_set_epi32((int)B[11], (int)B[6],  (int)B[1],  (int)B[12]);
    const __m128i o0 = x0, o1 = x1, o2 = x2, o3 = x3;

    for (int i = 0; i < 4; i++) {
        __m128i t;
        QR_SSE(x0, x1, x2, x3)

        __m128i y1 = _mm_shuffle_epi32(x3, 0x39);
        __m128i y2 = _mm_shuffle_epi32(x2, 0x4E);
        __m128i y3 = _mm_shuffle_epi32(x1, 0x93);

        QR_SSE(x0, y1, y2, y3)

        x1 = _mm_shuffle_epi32(y3, 0x39);
        x2 = _mm_shuffle_epi32(y2, 0x4E);
        x3 = _mm_shuffle_epi32(y1, 0x93);
    }

    x0 = _mm_add_epi32(x0, o0);
    x1 = _mm_add_epi32(x1, o1);
    x2 = _mm_add_epi32(x2, o2);
    x3 = _mm_add_epi32(x3, o3);

    uint32_t t0[4], t1[4], t2[4], t3[4];
    _mm_storeu_si128((__m128i *)t0, x0);
    _mm_storeu_si128((__m128i *)t1, x1);
    _mm_storeu_si128((__m128i *)t2, x2);
    _mm_storeu_si128((__m128i *)t3, x3);
    B[0]  = t0[0]; B[5]  = t0[1]; B[10] = t0[2]; B[15] = t0[3];
    B[4]  = t1[0]; B[9]  = t1[1]; B[14] = t1[2]; B[3]  = t1[3];
    B[8]  = t2[0]; B[13] = t2[1]; B[2]  = t2[2]; B[7]  = t2[3];
    B[12] = t3[0]; B[1]  = t3[1]; B[6]  = t3[2]; B[11] = t3[3];
}

#elif (defined(__ARM_NEON) || defined(__ARM_NEON__)) && !defined(KW_SCRYPT_PORTABLE)

#define ROTL_U32X4(v, c) vorrq_u32(vshlq_n_u32((v), (c)), vshrq_n_u32((v), 32 - (c)))

#define QR_NEON(a, b, cc, d) \
    t = vaddq_u32(a, d);  b  = veorq_u32(b,  ROTL_U32X4(t, 7));  \
    t = vaddq_u32(b, a);  cc = veorq_u32(cc, ROTL_U32X4(t, 9));  \
    t = vaddq_u32(cc, b); d  = veorq_u32(d,  ROTL_U32X4(t, 13)); \
    t = vaddq_u32(d, cc); a  = veorq_u32(a,  ROTL_U32X4(t, 18));

/* the lane layout and rotations are the SSE2 ones; see the comment there */
static void salsa20_8(uint32_t B[16])
{
    uint32_t l0[4] = { B[0],  B[5],  B[10], B[15] };
    uint32_t l1[4] = { B[4],  B[9],  B[14], B[3]  };
    uint32_t l2[4] = { B[8],  B[13], B[2],  B[7]  };
    uint32_t l3[4] = { B[12], B[1],  B[6],  B[11] };
    uint32x4_t x0 = vld1q_u32(l0), x1 = vld1q_u32(l1);
    uint32x4_t x2 = vld1q_u32(l2), x3 = vld1q_u32(l3);
    const uint32x4_t o0 = x0, o1 = x1, o2 = x2, o3 = x3;

    for (int i = 0; i < 4; i++) {
        uint32x4_t t;
        QR_NEON(x0, x1, x2, x3)

        uint32x4_t y1 = vextq_u32(x3, x3, 1);
        uint32x4_t y2 = vextq_u32(x2, x2, 2);
        uint32x4_t y3 = vextq_u32(x1, x1, 3);

        QR_NEON(x0, y1, y2, y3)

        x1 = vextq_u32(y3, y3, 1);
        x2 = vextq_u32(y2, y2, 2);
        x3 = vextq_u32(y1, y1, 3);
    }

    vst1q_u32(l0, vaddq_u32(x0, o0));
    vst1q_u32(l1, vaddq_u32(x1, o1));
    vst1q_u32(l2, vaddq_u32(x2, o2));
    vst1q_u32(l3, vaddq_u32(x3, o3));
    B[0]  = l0[0]; B[5]  = l0[1]; B[10] = l0[2]; B[15] = l0[3];
    B[4]  = l1[0]; B[9]  = l1[1]; B[14] = l1[2]; B[3]  = l1[3];
    B[8]  = l2[0]; B[13] = l2[1]; B[2]  = l2[2]; B[7]  = l2[3];
    B[12] = l3[0]; B[1]  = l3[1]; B[6]  = l3[2]; B[11] = l3[3];
}

#else

#define R(a, b) (((a) << (b)) | ((a) >> (32 - (b))))

static void salsa20_8(uint32_t B[16])
{
    uint32_t x[16];
    memcpy(x, B, sizeof x);
    for (int i = 0; i < 4; i++) {
        x[ 4] ^= R(x[ 0] + x[12],  7);  x[ 8] ^= R(x[ 4] + x[ 0],  9);
        x[12] ^= R(x[ 8] + x[ 4], 13);  x[ 0] ^= R(x[12] + x[ 8], 18);
        x[ 9] ^= R(x[ 5] + x[ 1],  7);  x[13] ^= R(x[ 9] + x[ 5],  9);
        x[ 1] ^= R(x[13] + x[ 9], 13);  x[ 5] ^= R(x[ 1] + x[13], 18);
        x[14] ^= R(x[10] + x[ 6],  7);  x[ 2] ^= R(x[14] + x[10],  9);
        x[ 6] ^= R(x[ 2] + x[14], 13);  x[10] ^= R(x[ 6] + x[ 2], 18);
        x[ 3] ^= R(x[15] + x[11],  7);  x[ 7] ^= R(x[ 3] + x[15],  9);
        x[11] ^= R(x[ 7] + x[ 3], 13);  x[15] ^= R(x[11] + x[ 7], 18);

        x[ 1] ^= R(x[ 0] + x[ 3],  7);  x[ 2] ^= R(x[ 1] + x[ 0],  9);
        x[ 3] ^= R(x[ 2] + x[ 1], 13);  x[ 0] ^= R(x[ 3] + x[ 2], 18);
        x[ 6] ^= R(x[ 5] + x[ 4],  7);  x[ 7] ^= R(x[ 6] + x[ 5],  9);
        x[ 4] ^= R(x[ 7] + x[ 6], 13);  x[ 5] ^= R(x[ 4] + x[ 7], 18);
        x[11] ^= R(x[10] + x[ 9],  7);  x[ 8] ^= R(x[11] + x[10],  9);
        x[ 9] ^= R(x[ 8] + x[11], 13);  x[10] ^= R(x[ 9] + x[ 8], 18);
        x[12] ^= R(x[15] + x[14],  7);  x[13] ^= R(x[12] + x[15],  9);
        x[14] ^= R(x[13] + x[12], 13);  x[15] ^= R(x[14] + x[13], 18);
    }
    for (int i = 0; i < 16; i++) B[i] += x[i];
}

#endif

/* ── BlockMix and ROMix ──────────────────────────────────────────────────
   Both work on 32-bit words rather than bytes: the scratchpad is only ever
   read back by this code, so the little-endian conversion happens once on the
   way in and once on the way out instead of 2048 times in between. */

/* B holds 2r 16-word blocks; the result is the even outputs then the odd ones */
static void blockmix(uint32_t *B, uint32_t *Y, uint32_t r)
{
    uint32_t X[16];
    memcpy(X, B + (2 * r - 1) * 16, 64);
    for (uint32_t i = 0; i < 2 * r; i++) {
        for (int k = 0; k < 16; k++) X[k] ^= B[i * 16 + k];
        salsa20_8(X);
        memcpy(Y + i * 16, X, 64);
    }
    for (uint32_t i = 0; i < r; i++) {
        memcpy(B + i * 16, Y + (2 * i) * 16, 64);
        memcpy(B + (r + i) * 16, Y + (2 * i + 1) * 16, 64);
    }
}

/* r == 1 collapses to two Salsa calls with no reordering, which is every call
   Dogecoin makes; keeping it separate drops the copies the general form needs */
static inline void blockmix_r1(uint32_t *B)
{
    for (int k = 0; k < 16; k++) B[k] ^= B[16 + k];
    salsa20_8(B);
    for (int k = 0; k < 16; k++) B[16 + k] ^= B[k];
    salsa20_8(B + 16);
}

static void romix_r1(uint32_t *X, uint32_t *V, uint64_t n)
{
    for (uint64_t i = 0; i < n; i++) {
        memcpy(V + i * 32, X, 128);
        blockmix_r1(X);
    }
    for (uint64_t i = 0; i < n; i++) {
        uint64_t j = X[16] & (n - 1);          /* Integerify: first word of the last block */
        const uint32_t *Vj = V + j * 32;
        for (int k = 0; k < 32; k++) X[k] ^= Vj[k];
        blockmix_r1(X);
    }
}

static void romix(uint32_t *X, uint32_t *V, uint32_t *Y, uint64_t n, uint32_t r)
{
    const size_t words = 32 * (size_t)r;
    for (uint64_t i = 0; i < n; i++) {
        memcpy(V + i * words, X, words * 4);
        blockmix(X, Y, r);
    }
    for (uint64_t i = 0; i < n; i++) {
        uint64_t j = X[(2 * r - 1) * 16] & (n - 1);
        const uint32_t *Vj = V + j * words;
        for (size_t k = 0; k < words; k++) X[k] ^= Vj[k];
        blockmix(X, Y, r);
    }
}

/* ── the public forms ────────────────────────────────────────────────── */

int kw_scrypt(const uint8_t *pass, size_t passlen,
              const uint8_t *salt, size_t saltlen,
              uint64_t n, uint32_t r, uint32_t p,
              uint8_t *out, size_t outlen)
{
    if (n < 2 || (n & (n - 1)) || r == 0 || p == 0 || !out || outlen == 0) return 0;
    /* 128*r*n must not overflow, and neither must 128*r*p */
    if (r > (1u << 20) || p > (1u << 20)) return 0;
    if (n > (uint64_t)SIZE_MAX / (128 * (uint64_t)r)) return 0;

    const size_t blocklen = 128 * (size_t)r;
    const size_t words = blocklen / 4;

    uint8_t *B = (uint8_t *)malloc(blocklen * p);
    uint32_t *V = (uint32_t *)malloc(blocklen * (size_t)n);
    uint32_t *X = (uint32_t *)malloc(blocklen);
    uint32_t *Y = (uint32_t *)malloc(blocklen);
    int ok = 0;
    if (!B || !V || !X || !Y) goto done;

    if (!kw_pbkdf2_hmac_sha256(pass, passlen, salt, saltlen, 1, B, blocklen * p)) goto done;

    for (uint32_t i = 0; i < p; i++) {
        const uint8_t *Bi = B + (size_t)i * blocklen;
        for (size_t k = 0; k < words; k++) X[k] = rd32(Bi + k * 4);
        if (r == 1) romix_r1(X, V, n); else romix(X, V, Y, n, r);
        for (size_t k = 0; k < words; k++) wr32(B + (size_t)i * blocklen + k * 4, X[k]);
    }

    ok = kw_pbkdf2_hmac_sha256(pass, passlen, B, blocklen * p, 1, out, outlen);

done:
    if (B) { kw_secure_zero(B, blocklen * p); free(B); }
    if (V) { kw_secure_zero(V, blocklen * (size_t)n); free(V); }
    if (X) { kw_secure_zero(X, blocklen); free(X); }
    if (Y) { kw_secure_zero(Y, blocklen); free(Y); }
    return ok;
}

/* Dogecoin's parameters, with the scratchpad supplied so a validator loop over
   millions of headers allocates once rather than per header. */
int kw_scrypt_pow(const uint8_t header[80], uint8_t out[32], void *scratch)
{
    uint32_t *V = (uint32_t *)scratch;
    void *owned = NULL;
    if (!V) {
        owned = malloc(KW_SCRYPT_SCRATCH);
        if (!owned) return 0;
        V = (uint32_t *)owned;
    }

    uint8_t B[128];
    uint32_t X[32];
    int ok = 0;

    if (!kw_pbkdf2_hmac_sha256(header, 80, header, 80, 1, B, sizeof B)) goto done;
    for (int k = 0; k < 32; k++) X[k] = rd32(B + k * 4);
    romix_r1(X, V, 1024);
    for (int k = 0; k < 32; k++) wr32(B + k * 4, X[k]);
    ok = kw_pbkdf2_hmac_sha256(header, 80, B, sizeof B, 1, out, 32);

done:
    kw_secure_zero(B, sizeof B);
    kw_secure_zero(X, sizeof X);
    free(owned);
    return ok;
}

/* ROMix on KW_SCRYPT_BATCH independent states, stepped together. Each state's
   second loop reads its scratchpad at a data-dependent index, which is a cache
   miss that nothing in that state can cover; interleaving lets the other
   states' Salsa rounds run underneath it. */
static void romix_r1_batch(uint32_t X[][32], uint32_t *V[], uint64_t n, size_t lanes)
{
    for (uint64_t i = 0; i < n; i++)
        for (size_t l = 0; l < lanes; l++) {
            memcpy(V[l] + i * 32, X[l], 128);
            blockmix_r1(X[l]);
        }
    for (uint64_t i = 0; i < n; i++) {
        uint64_t j[KW_SCRYPT_BATCH];
        for (size_t l = 0; l < lanes; l++) {
            j[l] = X[l][16] & (n - 1);
            __builtin_prefetch(V[l] + j[l] * 32, 0, 0);
        }
        for (size_t l = 0; l < lanes; l++) {
            const uint32_t *Vj = V[l] + j[l] * 32;
            for (int k = 0; k < 32; k++) X[l][k] ^= Vj[k];
            blockmix_r1(X[l]);
        }
    }
}

int kw_scrypt_pow_batch(const uint8_t *headers, size_t count,
                        uint8_t *out, void *scratch)
{
    if (!headers || !out) return 0;
    if (count == 0) return 1;

    void *owned = NULL;
    uint8_t *base = (uint8_t *)scratch;
    if (!base) {
        owned = malloc((size_t)KW_SCRYPT_SCRATCH * KW_SCRYPT_BATCH);
        if (!owned) return 0;
        base = (uint8_t *)owned;
    }

    uint32_t *V[KW_SCRYPT_BATCH];
    for (int l = 0; l < KW_SCRYPT_BATCH; l++)
        V[l] = (uint32_t *)(base + (size_t)l * KW_SCRYPT_SCRATCH);

    uint8_t B[KW_SCRYPT_BATCH][128];
    uint32_t X[KW_SCRYPT_BATCH][32];
    int ok = 1;
    size_t i = 0;

    for (; i + KW_SCRYPT_BATCH <= count && ok; i += KW_SCRYPT_BATCH) {
        for (int l = 0; l < KW_SCRYPT_BATCH; l++) {
            const uint8_t *h = headers + (i + (size_t)l) * 80;
            if (!kw_pbkdf2_hmac_sha256(h, 80, h, 80, 1, B[l], 128)) { ok = 0; break; }
            for (int k = 0; k < 32; k++) X[l][k] = rd32(B[l] + k * 4);
        }
        if (!ok) break;
        romix_r1_batch(X, V, 1024, KW_SCRYPT_BATCH);
        for (int l = 0; l < KW_SCRYPT_BATCH; l++) {
            const uint8_t *h = headers + (i + (size_t)l) * 80;
            for (int k = 0; k < 32; k++) wr32(B[l] + k * 4, X[l][k]);
            if (!kw_pbkdf2_hmac_sha256(h, 80, B[l], 128, 1, out + (i + (size_t)l) * 32, 32)) ok = 0;
        }
    }
    for (; i < count && ok; i++)
        ok = kw_scrypt_pow(headers + i * 80, out + i * 32, V[0]);

    kw_secure_zero(B, sizeof B);
    kw_secure_zero(X, sizeof X);
    free(owned);
    return ok;
}
