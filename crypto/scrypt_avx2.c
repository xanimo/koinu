/* koinu.dog - the eight-at-once scrypt core, AVX2
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * The SSE2 core in scrypt.c holds one state across four lanes, which costs a
 * shuffle between every column round and row round because the quarter-rounds
 * change which words travel together, and leaves the whole thing latency-bound:
 * one dependency chain, four lanes wide, and nothing to fill the other issue
 * slots with.
 *
 * This core transposes instead. Vector k holds word k of all eight states, so
 * Salsa20/8 is the scalar index pattern with vectors substituted for words: no
 * shuffles at all, eight hashes per pass, and the four quarter-rounds of a round
 * are independent chains the machine can interleave.
 *
 * What the layout costs is the scratchpad. Each state reads its own block at its
 * own data-dependent index, so the eight blocks are in eight places and have to
 * be transposed on the way in and out: 96 shuffles an iteration against Salsa's
 * 1280 vector operations. Keeping the eight scratchpads separate is what keeps
 * that cheap. Interleaving them by lane would remove the transposes, but then one
 * iteration would touch 8KB of cache lines to use 1KB of them.
 *
 * Held against the scalar core over random headers in test/test_scrypt.c. */

#include "scrypt_avx2.h"

#if defined(KW_SCRYPT_AVX2)

#include <immintrin.h>

/* The target attribute rather than a -mavx2 translation unit: the build stays a
   flat source list, and the binary still runs on a CPU without AVX2. */
#define AVX2 __attribute__((target("avx2")))

#define ROTL(v, c) _mm256_or_si256(_mm256_slli_epi32((v), (c)), _mm256_srli_epi32((v), 32 - (c)))
#define S(d, a, b, r) x##d = _mm256_xor_si256(x##d, ROTL(_mm256_add_epi32(x##a, x##b), r))

/* a column round then a row round, which is the scalar core's index pattern
   line for line */
#define DOUBLE_ROUND                                                               \
    S( 4,  0, 12,  7);  S( 8,  4,  0,  9);  S(12,  8,  4, 13);  S( 0, 12,  8, 18); \
    S( 9,  5,  1,  7);  S(13,  9,  5,  9);  S( 1, 13,  9, 13);  S( 5,  1, 13, 18); \
    S(14, 10,  6,  7);  S( 2, 14, 10,  9);  S( 6,  2, 14, 13);  S(10,  6,  2, 18); \
    S( 3, 15, 11,  7);  S( 7,  3, 15,  9);  S(11,  7,  3, 13);  S(15, 11,  7, 18); \
                                                                                   \
    S( 1,  0,  3,  7);  S( 2,  1,  0,  9);  S( 3,  2,  1, 13);  S( 0,  3,  2, 18); \
    S( 6,  5,  4,  7);  S( 7,  6,  5,  9);  S( 4,  7,  6, 13);  S( 5,  4,  7, 18); \
    S(11, 10,  9,  7);  S( 8, 11, 10,  9);  S( 9,  8, 11, 13);  S(10,  9,  8, 18); \
    S(12, 15, 14,  7);  S(13, 12, 15,  9);  S(14, 13, 12, 13);  S(15, 14, 13, 18);

/* B[0..15] are words 0..15 of the eight states. Sixteen live vectors against
   sixteen registers, so the shape of the source decides how much of the state
   ends up on the stack: named locals and the rounds written out cost gcc 235ns
   a ROMix iteration here, where an array and a loop cost 286. */
static AVX2 void salsa20_8x8(__m256i *B)
{
    __m256i x0 = B[0], x1 = B[1], x2 = B[2], x3 = B[3];
    __m256i x4 = B[4], x5 = B[5], x6 = B[6], x7 = B[7];
    __m256i x8 = B[8], x9 = B[9], x10 = B[10], x11 = B[11];
    __m256i x12 = B[12], x13 = B[13], x14 = B[14], x15 = B[15];

    DOUBLE_ROUND
    DOUBLE_ROUND
    DOUBLE_ROUND
    DOUBLE_ROUND

    B[0] = _mm256_add_epi32(B[0], x0);      B[1] = _mm256_add_epi32(B[1], x1);
    B[2] = _mm256_add_epi32(B[2], x2);      B[3] = _mm256_add_epi32(B[3], x3);
    B[4] = _mm256_add_epi32(B[4], x4);      B[5] = _mm256_add_epi32(B[5], x5);
    B[6] = _mm256_add_epi32(B[6], x6);      B[7] = _mm256_add_epi32(B[7], x7);
    B[8] = _mm256_add_epi32(B[8], x8);      B[9] = _mm256_add_epi32(B[9], x9);
    B[10] = _mm256_add_epi32(B[10], x10);   B[11] = _mm256_add_epi32(B[11], x11);
    B[12] = _mm256_add_epi32(B[12], x12);   B[13] = _mm256_add_epi32(B[13], x13);
    B[14] = _mm256_add_epi32(B[14], x14);   B[15] = _mm256_add_epi32(B[15], x15);
}

/* 8x8 transpose of 32-bit words, which is its own inverse: in[l] holding eight
   consecutive words of state l becomes out[k] holding word k of all eight. */
static AVX2 void t8(const __m256i *in, __m256i *out)
{
    __m256i a0 = _mm256_unpacklo_epi32(in[0], in[1]);
    __m256i a1 = _mm256_unpackhi_epi32(in[0], in[1]);
    __m256i a2 = _mm256_unpacklo_epi32(in[2], in[3]);
    __m256i a3 = _mm256_unpackhi_epi32(in[2], in[3]);
    __m256i a4 = _mm256_unpacklo_epi32(in[4], in[5]);
    __m256i a5 = _mm256_unpackhi_epi32(in[4], in[5]);
    __m256i a6 = _mm256_unpacklo_epi32(in[6], in[7]);
    __m256i a7 = _mm256_unpackhi_epi32(in[6], in[7]);

    __m256i b0 = _mm256_unpacklo_epi64(a0, a2);
    __m256i b1 = _mm256_unpackhi_epi64(a0, a2);
    __m256i b2 = _mm256_unpacklo_epi64(a1, a3);
    __m256i b3 = _mm256_unpackhi_epi64(a1, a3);
    __m256i b4 = _mm256_unpacklo_epi64(a4, a6);
    __m256i b5 = _mm256_unpackhi_epi64(a4, a6);
    __m256i b6 = _mm256_unpacklo_epi64(a5, a7);
    __m256i b7 = _mm256_unpackhi_epi64(a5, a7);

    out[0] = _mm256_permute2x128_si256(b0, b4, 0x20);
    out[1] = _mm256_permute2x128_si256(b1, b5, 0x20);
    out[2] = _mm256_permute2x128_si256(b2, b6, 0x20);
    out[3] = _mm256_permute2x128_si256(b3, b7, 0x20);
    out[4] = _mm256_permute2x128_si256(b0, b4, 0x31);
    out[5] = _mm256_permute2x128_si256(b1, b5, 0x31);
    out[6] = _mm256_permute2x128_si256(b2, b6, 0x31);
    out[7] = _mm256_permute2x128_si256(b3, b7, 0x31);
}

/* blk[l] is state l's 32-word block. loadT reads them into the transposed form,
   xorT reads and accumulates, storeT writes it back out. */
static AVX2 void loadT(__m256i X[32], const uint32_t *const blk[8])
{
    for (int g = 0; g < 4; g++) {
        __m256i in[8];
        for (int l = 0; l < 8; l++) in[l] = _mm256_loadu_si256((const __m256i *)(blk[l] + g * 8));
        t8(in, X + g * 8);
    }
}

static AVX2 void xorT(__m256i X[32], const uint32_t *const blk[8])
{
    for (int g = 0; g < 4; g++) {
        __m256i in[8], tr[8];
        for (int l = 0; l < 8; l++) in[l] = _mm256_loadu_si256((const __m256i *)(blk[l] + g * 8));
        t8(in, tr);
        for (int k = 0; k < 8; k++) X[g * 8 + k] = _mm256_xor_si256(X[g * 8 + k], tr[k]);
    }
}

static AVX2 void storeT(uint32_t *const blk[8], const __m256i X[32])
{
    for (int g = 0; g < 4; g++) {
        __m256i out[8];
        t8(X + g * 8, out);
        for (int l = 0; l < 8; l++) _mm256_storeu_si256((__m256i *)(blk[l] + g * 8), out[l]);
    }
}

/* the r=1 BlockMix of scrypt.c, on eight states */
static AVX2 void blockmix8(__m256i X[32])
{
    for (int k = 0; k < 16; k++) X[k] = _mm256_xor_si256(X[k], X[16 + k]);
    salsa20_8x8(X);
    for (int k = 0; k < 16; k++) X[16 + k] = _mm256_xor_si256(X[16 + k], X[k]);
    salsa20_8x8(X + 16);
}

AVX2 void kw_scrypt_romix8_avx2(uint32_t X[8][32], uint32_t *const V[8], uint64_t n)
{
    __m256i T[32];
    const uint32_t *rd[8];
    uint32_t *wr[8];

    for (int l = 0; l < 8; l++) rd[l] = X[l];
    loadT(T, rd);

    for (uint64_t i = 0; i < n; i++) {
        for (int l = 0; l < 8; l++) wr[l] = V[l] + i * 32;
        storeT(wr, T);
        blockmix8(T);
    }

    for (uint64_t i = 0; i < n; i++) {
        uint32_t j[8];
        _mm256_storeu_si256((__m256i *)j, T[16]);       /* Integerify, eight at once */
        for (int l = 0; l < 8; l++) rd[l] = V[l] + (size_t)(j[l] & (uint32_t)(n - 1)) * 32;
        xorT(T, rd);
        blockmix8(T);
    }

    for (int l = 0; l < 8; l++) wr[l] = X[l];
    storeT(wr, T);
}

#else

/* not x86_64: nothing here, and scrypt.c never refers to it */
typedef int kw_scrypt_avx2_not_on_this_arch;

#endif
