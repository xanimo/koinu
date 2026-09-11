/* koinu.dog - SHA-256 on the instructions the CPU has for it
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * x86 has had a SHA-256 round instruction since Goldmont and Zen, and ARMv8 has one
 * as a crypto extension. Both compute two rounds at a time and keep the message
 * schedule in vector registers, which is several times the scalar core's rate.
 *
 * Neither is compiled for unconditionally: the functions carry their own target
 * attribute, so the build stays one flat source list and the binary still runs where
 * the instructions are absent. crypto/cpu.c decides at run time.
 *
 * These two cores are the only code in the tree I have not executed. This laptop has
 * no SHA extension, and no emulator was to hand, so the x86 core has been read
 * against Intel's sequence and compiled but never run by me; the ARM core runs on
 * macOS arm64 in CI. That is the reason for the self-check below rather than a
 * comment promising care: before either core is used for anything, it hashes a block
 * and is held against the scalar core, and a core that disagrees is switched off for
 * the life of the process. A wrong hash is not a performance problem, it is a wallet
 * that agrees with nobody, so the cost of one compression at startup is not a
 * question worth asking. */

#include "sha2.h"
#include "cpu.h"

#include <stdatomic.h>
#include <string.h>

#if defined(__x86_64__) || defined(__i386__)
#define KW_SHA2_HW_X86 1
#include <immintrin.h>
#define SHA_NI __attribute__((target("sha,sse4.1,ssse3")))

/* Intel's sequence: the state is held as ABEF and CDGH rather than a..h, the schedule
   advances four words at a time, and each sha256rnds2 does two rounds. */
SHA_NI static void compress_ni(uint32_t state[8], const uint8_t *p)
{
    const __m128i SWAP = _mm_set_epi64x((long long)0x0c0d0e0f08090a0bULL,
                                        (long long)0x0405060700010203ULL);
    __m128i tmp = _mm_loadu_si128((const __m128i *)&state[0]);   /* a b c d */
    __m128i s1  = _mm_loadu_si128((const __m128i *)&state[4]);   /* e f g h */

    tmp = _mm_shuffle_epi32(tmp, 0xB1);                          /* b a d c */
    s1  = _mm_shuffle_epi32(s1, 0x1B);                           /* h g f e */
    __m128i s0 = _mm_alignr_epi8(tmp, s1, 8);                    /* a b e f */
    s1 = _mm_blend_epi16(s1, tmp, 0xF0);                         /* c d g h */

    const __m128i abef_save = s0, cdgh_save = s1;

    __m128i m0 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(p +  0)), SWAP);
    __m128i m1 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(p + 16)), SWAP);
    __m128i m2 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(p + 32)), SWAP);
    __m128i m3 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(p + 48)), SWAP);
    __m128i msg;

/* four rounds against the four constants for this quarter, then the schedule step */
#define KW_NI_ROUNDS(w, k0, k1)                                                    \
    msg = _mm_add_epi32((w), _mm_set_epi64x((long long)(k1), (long long)(k0)));    \
    s1 = _mm_sha256rnds2_epu32(s1, s0, msg);                                       \
    msg = _mm_shuffle_epi32(msg, 0x0E);                                            \
    s0 = _mm_sha256rnds2_epu32(s0, s1, msg)

#define KW_NI_SCHED(a, b, c, d)                                                    \
    (a) = _mm_sha256msg1_epu32((a), (b));                                          \
    (a) = _mm_add_epi32((a), _mm_alignr_epi8((d), (c), 4));                        \
    (a) = _mm_sha256msg2_epu32((a), (d))

    KW_NI_ROUNDS(m0, 0x71374491428a2f98ULL, 0xe9b5dba5b5c0fbcfULL);
    KW_NI_ROUNDS(m1, 0x59f111f13956c25bULL, 0xab1c5ed5923f82a4ULL);
    KW_NI_SCHED(m0, m1, m2, m3);
    KW_NI_ROUNDS(m2, 0x12835b01d807aa98ULL, 0x550c7dc3243185beULL);
    KW_NI_SCHED(m1, m2, m3, m0);
    KW_NI_ROUNDS(m3, 0x80deb1fe72be5d74ULL, 0xc19bf1749bdc06a7ULL);
    KW_NI_SCHED(m2, m3, m0, m1);
    KW_NI_ROUNDS(m0, 0xefbe4786e49b69c1ULL, 0x240ca1cc0fc19dc6ULL);
    KW_NI_SCHED(m3, m0, m1, m2);
    KW_NI_ROUNDS(m1, 0x4a7484aa2de92c6fULL, 0x76f988da5cb0a9dcULL);
    KW_NI_SCHED(m0, m1, m2, m3);
    KW_NI_ROUNDS(m2, 0xa831c66d983e5152ULL, 0xbf597fc7b00327c8ULL);
    KW_NI_SCHED(m1, m2, m3, m0);
    KW_NI_ROUNDS(m3, 0xd5a79147c6e00bf3ULL, 0x1429296706ca6351ULL);
    KW_NI_SCHED(m2, m3, m0, m1);
    KW_NI_ROUNDS(m0, 0x2e1b213827b70a85ULL, 0x53380d134d2c6dfcULL);
    KW_NI_SCHED(m3, m0, m1, m2);
    KW_NI_ROUNDS(m1, 0x766a0abb650a7354ULL, 0x92722c8581c2c92eULL);
    KW_NI_SCHED(m0, m1, m2, m3);
    KW_NI_ROUNDS(m2, 0xa81a664ba2bfe8a1ULL, 0xc76c51a3c24b8b70ULL);
    KW_NI_SCHED(m1, m2, m3, m0);
    KW_NI_ROUNDS(m3, 0xd6990624d192e819ULL, 0x106aa070f40e3585ULL);
    KW_NI_SCHED(m2, m3, m0, m1);
    KW_NI_ROUNDS(m0, 0x1e376c0819a4c116ULL, 0x34b0bcb52748774cULL);
    KW_NI_SCHED(m3, m0, m1, m2);
    KW_NI_ROUNDS(m1, 0x4ed8aa4a391c0cb3ULL, 0x682e6ff35b9cca4fULL);
    KW_NI_ROUNDS(m2, 0x78a5636f748f82eeULL, 0x8cc7020884c87814ULL);
    KW_NI_ROUNDS(m3, 0xa4506ceb90befffaULL, 0xc67178f2bef9a3f7ULL);

#undef KW_NI_ROUNDS
#undef KW_NI_SCHED

    s0 = _mm_add_epi32(s0, abef_save);
    s1 = _mm_add_epi32(s1, cdgh_save);

    tmp = _mm_shuffle_epi32(s0, 0x1B);                           /* f e b a */
    s1  = _mm_shuffle_epi32(s1, 0xB1);                           /* d c h g */
    s0  = _mm_blend_epi16(tmp, s1, 0xF0);                        /* d c b a */
    s1  = _mm_alignr_epi8(s1, tmp, 8);                           /* h g f e */

    _mm_storeu_si128((__m128i *)&state[0], s0);
    _mm_storeu_si128((__m128i *)&state[4], s1);
}

#elif defined(__aarch64__)
#define KW_SHA2_HW_ARM 1
#include <arm_neon.h>
#if defined(__clang__)
#define SHA_ARM __attribute__((target("crypto")))
#else
#define SHA_ARM __attribute__((target("+crypto")))
#endif

extern const uint32_t kw_sha256_k[64];

SHA_ARM static void compress_arm(uint32_t state[8], const uint8_t *p)
{
    uint32x4_t abcd = vld1q_u32(&state[0]), efgh = vld1q_u32(&state[4]);
    const uint32x4_t abcd0 = abcd, efgh0 = efgh;

    uint32x4_t m0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p +  0)));
    uint32x4_t m1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p + 16)));
    uint32x4_t m2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p + 32)));
    uint32x4_t m3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p + 48)));

    uint32x4_t t0, t1, tmp;
    t0 = vaddq_u32(m0, vld1q_u32(&kw_sha256_k[0]));

/* Four rounds. (mnext) is the message the quarter after this one consumes, added to
   its constants here so the addition overlaps the hashing. */
#define KW_ARM_QUARTER(mnext, kidx)                             \
    tmp = abcd;                                                 \
    t1 = vaddq_u32((mnext), vld1q_u32(&kw_sha256_k[kidx]));     \
    abcd = vsha256hq_u32(abcd, efgh, t0);                       \
    efgh = vsha256h2q_u32(efgh, tmp, t0);                       \
    t0 = t1

/* The schedule for the four rounds sixteen ahead. Neither half touches the state, so
   both can sit before the quarter rather than around it. */
#define KW_ARM_SCHED(a, b, c, d)                                \
    (a) = vsha256su0q_u32((a), (b));                            \
    (a) = vsha256su1q_u32((a), (c), (d))

    /* rounds 0 to 47: twelve quarters, each scheduling one message ahead */
    KW_ARM_SCHED(m0, m1, m2, m3);  KW_ARM_QUARTER(m1, 4);
    KW_ARM_SCHED(m1, m2, m3, m0);  KW_ARM_QUARTER(m2, 8);
    KW_ARM_SCHED(m2, m3, m0, m1);  KW_ARM_QUARTER(m3, 12);
    KW_ARM_SCHED(m3, m0, m1, m2);  KW_ARM_QUARTER(m0, 16);
    KW_ARM_SCHED(m0, m1, m2, m3);  KW_ARM_QUARTER(m1, 20);
    KW_ARM_SCHED(m1, m2, m3, m0);  KW_ARM_QUARTER(m2, 24);
    KW_ARM_SCHED(m2, m3, m0, m1);  KW_ARM_QUARTER(m3, 28);
    KW_ARM_SCHED(m3, m0, m1, m2);  KW_ARM_QUARTER(m0, 32);
    KW_ARM_SCHED(m0, m1, m2, m3);  KW_ARM_QUARTER(m1, 36);
    KW_ARM_SCHED(m1, m2, m3, m0);  KW_ARM_QUARTER(m2, 40);
    KW_ARM_SCHED(m2, m3, m0, m1);  KW_ARM_QUARTER(m3, 44);
    KW_ARM_SCHED(m3, m0, m1, m2);  KW_ARM_QUARTER(m0, 48);

    /* rounds 48 to 59: the messages are all scheduled, so only the hashing is left */
    KW_ARM_QUARTER(m1, 52);
    KW_ARM_QUARTER(m2, 56);
    KW_ARM_QUARTER(m3, 60);

    /* rounds 60 to 63: nothing follows, so there is no next message to add */
    tmp = abcd;
    abcd = vsha256hq_u32(abcd, efgh, t0);
    efgh = vsha256h2q_u32(efgh, tmp, t0);

#undef KW_ARM_QUARTER
#undef KW_ARM_SCHED

    vst1q_u32(&state[0], vaddq_u32(abcd, abcd0));
    vst1q_u32(&state[4], vaddq_u32(efgh, efgh0));
}

#endif

/* ── choosing, and proving the choice ─────────────────────────────────────── */

#define KW_SHA2_HW_UNASKED 0
#define KW_SHA2_HW_NO      1
#define KW_SHA2_HW_YES     2

static _Atomic int hw_state;

/* One block through both cores. Any difference and the hardware core is refused for
   the rest of the process: this is the check that stands in for a machine I could
   run it on. */
static int hw_agrees(void)
{
#if defined(KW_SHA2_HW_X86) || defined(KW_SHA2_HW_ARM)
    static const uint8_t block[64] = {
        'a','b','c',0x80, 0,0,0,0, 0,0,0,0, 0,0,0,0,
        0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
        0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
        0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,24
    };
    static const uint32_t iv[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    /* the digest of "abc", which is the one SHA-256 vector everyone knows */
    static const uint32_t want[8] = {
        0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223,
        0xb00361a3, 0x96177a9c, 0xb410ff61, 0xf20015ad
    };
    uint32_t got[8];
    memcpy(got, iv, sizeof got);
#if defined(KW_SHA2_HW_X86)
    compress_ni(got, block);
#else
    compress_arm(got, block);
#endif
    return memcmp(got, want, sizeof want) == 0;
#else
    return 0;
#endif
}

int kw_sha256_hw(void)
{
    int st = atomic_load_explicit(&hw_state, memory_order_relaxed);
    if (st == KW_SHA2_HW_UNASKED) {
        st = KW_SHA2_HW_NO;
#if defined(KW_SHA2_HW_X86)
        if (kw_cpu_has(KW_CPU_SHANI | KW_CPU_SSE41 | KW_CPU_SSSE3) && hw_agrees())
            st = KW_SHA2_HW_YES;
#elif defined(KW_SHA2_HW_ARM)
        if (kw_cpu_has(KW_CPU_SHA2) && hw_agrees()) st = KW_SHA2_HW_YES;
#endif
        atomic_store_explicit(&hw_state, st, memory_order_relaxed);
    }
    return st == KW_SHA2_HW_YES;
}

void kw_sha256_compress_hw(uint32_t h[8], const uint8_t *p)
{
#if defined(KW_SHA2_HW_X86)
    compress_ni(h, p);
#elif defined(KW_SHA2_HW_ARM)
    compress_arm(h, p);
#else
    (void)h; (void)p;      /* never called: kw_sha256_hw() is 0 here */
#endif
}

const char *kw_sha256_backend(void)
{
#if defined(KW_SHA2_HW_X86)
    return kw_sha256_hw() ? "sha-ni" : "scalar";
#elif defined(KW_SHA2_HW_ARM)
    return kw_sha256_hw() ? "armv8-sha2" : "scalar";
#else
    return "scalar";
#endif
}
