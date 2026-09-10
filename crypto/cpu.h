/* koinu.dog - what this CPU can do, asked once
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * One place that answers "does this machine have AVX2, SHA-NI, the ARM crypto
 * extensions", so a core in crypto/ dispatches on a bit rather than carrying its
 * own detection. x86 and ARM share one mask: a bit that cannot exist on the build
 * target is never set, so asking is always safe, though the code being dispatched
 * to still needs its own #ifdef to exist at all.
 *
 * Detection is not the same question as compilation. -mavx2 says the compiler may
 * emit it; these bits say the CPU will run it.
 *
 * Not named cpuid.h: the build puts crypto/ on the include path, so that name
 * would shadow the compiler's own <cpuid.h> for every file in the tree. */

#ifndef KOINU_CPU_H
#define KOINU_CPU_H

#include <stddef.h>
#include <stdint.h>

enum {
    /* x86 */
    KW_CPU_SSE2      = 1u << 0,
    KW_CPU_SSSE3     = 1u << 1,
    KW_CPU_SSE41     = 1u << 2,
    KW_CPU_AVX       = 1u << 3,
    KW_CPU_AVX2      = 1u << 4,
    KW_CPU_AVX512F   = 1u << 5,
    KW_CPU_AVX512VL  = 1u << 6,
    KW_CPU_SHANI     = 1u << 7,     /* sha1/sha256 in one instruction */
    KW_CPU_AESNI     = 1u << 8,
    KW_CPU_PCLMUL    = 1u << 9,
    KW_CPU_BMI2      = 1u << 10,

    /* ARM */
    KW_CPU_NEON      = 1u << 16,
    KW_CPU_ARM_AES   = 1u << 17,
    KW_CPU_PMULL     = 1u << 18,
    KW_CPU_SHA1      = 1u << 19,
    KW_CPU_SHA2      = 1u << 20,    /* sha256, the armv8 crypto extension */
    KW_CPU_SHA512    = 1u << 21,
    KW_CPU_CRC32     = 1u << 22
};

/* The whole mask, detected on the first call and cached. */
uint32_t kw_cpu_features(void);

/* 1 if every bit in (want) is present, so several can be asked at once. */
int kw_cpu_has(uint32_t want);

/* The names of what is present, space separated, e.g. "sse2 ssse3 sse4_1 avx
   avx2 aesni pclmulqdq bmi2". Truncated to fit (len) including the terminator,
   never past it. Returns (buf). */
char *kw_cpu_summary(char *buf, size_t len);

#endif /* KOINU_CPU_H */
