/* koinu.dog - cpu feature detection tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Detection cannot be checked against a vector, so it is checked three ways: the
 * implications between extensions must hold, the mask must not change between
 * calls, and on x86 every bit is held against __builtin_cpu_supports, which is a
 * separate implementation of the same question in the compiler's runtime. What
 * that last one cannot catch is both agreeing and both being wrong, so the
 * summary is printed for a human to compare against /proc/cpuinfo. */

#include "cpu.h"
#include "scrypt.h"

#include <stdio.h>
#include <string.h>

static int fail, checked;

static void implies(uint32_t f, uint32_t a, uint32_t b, const char *what)
{
    checked++;
    if ((f & a) && !(f & b)) { fprintf(stderr, "FAIL: %s\n", what); fail = 1; }
}

int main(void)
{
    uint32_t f = kw_cpu_features();

    if (f != kw_cpu_features()) { fprintf(stderr, "FAIL: the mask changed between calls\n"); return 1; }
    if (f & (1u << 31)) { fprintf(stderr, "FAIL: the cache marker leaked into the mask\n"); return 1; }

    implies(f, KW_CPU_AVX2, KW_CPU_AVX, "avx2 without avx");
    implies(f, KW_CPU_AVX, KW_CPU_SSE2, "avx without sse2");
    implies(f, KW_CPU_SSE41, KW_CPU_SSSE3, "sse4_1 without ssse3");
    implies(f, KW_CPU_SSSE3, KW_CPU_SSE2, "ssse3 without sse2");
    implies(f, KW_CPU_AVX512F, KW_CPU_AVX2, "avx512f without avx2");
    implies(f, KW_CPU_AVX512VL, KW_CPU_AVX512F, "avx512vl without avx512f");
    implies(f, KW_CPU_SHA512, KW_CPU_SHA2, "arm sha512 without sha2");
    implies(f, KW_CPU_ARM_AES, KW_CPU_NEON, "arm aes without neon");
    implies(f, KW_CPU_SHA2, KW_CPU_NEON, "arm sha2 without neon");

    /* kw_cpu_has takes several bits at once and must want all of them */
    if (kw_cpu_has(KW_CPU_AVX2) != ((f & KW_CPU_AVX2) != 0))
        { fprintf(stderr, "FAIL: has() disagrees with the mask\n"); return 1; }
    if (kw_cpu_has(KW_CPU_AVX2 | KW_CPU_AVX512F) && !kw_cpu_has(KW_CPU_AVX512F))
        { fprintf(stderr, "FAIL: has() is an or, not an and\n"); return 1; }
    if (!kw_cpu_has(0)) { fprintf(stderr, "FAIL: has(nothing) must hold\n"); return 1; }

    /* what the build target guarantees regardless of the model */
#if defined(__x86_64__)
    if (!(f & KW_CPU_SSE2)) { fprintf(stderr, "FAIL: x86_64 without sse2\n"); return 1; }
#endif
#if defined(__aarch64__)
    if (!(f & KW_CPU_NEON)) { fprintf(stderr, "FAIL: aarch64 without neon\n"); return 1; }
#endif
#if !defined(__x86_64__) && !defined(__i386__)
    if (f & (KW_CPU_SSE2 | KW_CPU_AVX2 | KW_CPU_SHANI))
        { fprintf(stderr, "FAIL: x86 bits set off x86\n"); return 1; }
#endif
#if !defined(__aarch64__) && !defined(__arm__)
    if (f & (KW_CPU_NEON | KW_CPU_SHA2))
        { fprintf(stderr, "FAIL: arm bits set off arm\n"); return 1; }
#endif

    int crosschecked = 0;
#if defined(__x86_64__) || defined(__i386__)
    /* gcc and clang answer this from their own cpuid call in libgcc's startup
       code, so a disagreement means one of the two bit tables is wrong. The
       argument has to be a literal, hence a macro rather than a loop. */
#define CROSS(bit, lit)                                                        \
    do {                                                                       \
        int ours = (f & (bit)) != 0, theirs = !!__builtin_cpu_supports(lit);    \
        if (ours != theirs) {                                                  \
            fprintf(stderr, "FAIL: " lit ": this file says %d, the compiler "  \
                            "says %d\n", ours, theirs);                        \
            fail = 1;                                                          \
        }                                                                      \
        crosschecked++;                                                        \
    } while (0)

    CROSS(KW_CPU_SSE2, "sse2");
    CROSS(KW_CPU_SSSE3, "ssse3");
    CROSS(KW_CPU_SSE41, "sse4.1");
    CROSS(KW_CPU_AVX, "avx");
    CROSS(KW_CPU_AVX2, "avx2");
    CROSS(KW_CPU_AVX512F, "avx512f");
    CROSS(KW_CPU_AVX512VL, "avx512vl");
    CROSS(KW_CPU_AESNI, "aes");
    CROSS(KW_CPU_PCLMUL, "pclmul");
    CROSS(KW_CPU_BMI2, "bmi2");
#if !defined(__clang__)
    CROSS(KW_CPU_SHANI, "sha");     /* clang 14 rejects this name in the builtin */
#endif
#endif

    /* the one dispatch site there is must agree with the bit it dispatches on */
    const char *batch = kw_scrypt_batch_backend();
#if defined(__x86_64__)
    if ((strcmp(batch, "avx2x8") == 0) != ((f & KW_CPU_AVX2) != 0))
        { fprintf(stderr, "FAIL: scrypt picked %s against the avx2 bit\n", batch); return 1; }
#endif

    char buf[256];
    kw_cpu_summary(buf, sizeof buf);

    /* truncation must stop on a whole name and still terminate */
    char small[6];
    kw_cpu_summary(small, sizeof small);
    if (strlen(small) >= sizeof small) { fprintf(stderr, "FAIL: summary overran\n"); return 1; }
    if (small[0] && strncmp(buf, small, strlen(small)) != 0)
        { fprintf(stderr, "FAIL: truncated summary is not a prefix: '%s'\n", small); return 1; }
    char none[1];
    kw_cpu_summary(none, sizeof none);
    if (none[0] != '\0') { fprintf(stderr, "FAIL: one byte of room is the terminator\n"); return 1; }

    if (fail) return 1;
    printf("cpu ok: %d implications, %d bits against the compiler's own detection,\n"
           "  scrypt batch %s\n  this cpu: %s\n",
           checked, crosschecked, batch, buf[0] ? buf : "nothing detected");
    return 0;
}
