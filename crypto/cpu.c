/* koinu.dog - runtime CPU feature detection
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * On x86 the bits come from CPUID leaf 1 and leaf 7, with the bit numbers spelled
 * out here rather than taken from the compiler's <cpuid.h> names, so the table can
 * be read against the Intel SDM without a second header. AVX is the one that
 * needs more than a feature bit: the OS has to have enabled ymm state, or the
 * first vector instruction faults, so OSXSAVE and XCR0 are checked too.
 *
 * On ARM the kernel answers instead of the CPU, since the ID registers are not
 * readable from user space: AT_HWCAP on Linux, sysctl on macOS. On anything else
 * only what the architecture guarantees is reported.
 *
 * The whole file is one cached word. test/test_cpu.c holds it against the
 * compiler's own __builtin_cpu_supports where that exists. */

#include "cpu.h"

#define KW_CPU_DETECTED (1u << 31)      /* so the cache is one word, 0 meaning unasked */

#if defined(__x86_64__) || defined(__i386__)

#include <cpuid.h>

/* leaf 1, ecx */
#define ECX1_PCLMUL   (1u << 1)
#define ECX1_SSSE3    (1u << 9)
#define ECX1_SSE41    (1u << 19)
#define ECX1_AESNI    (1u << 25)
#define ECX1_OSXSAVE  (1u << 27)
#define ECX1_AVX      (1u << 28)
/* leaf 1, edx */
#define EDX1_SSE2     (1u << 26)
/* leaf 7 subleaf 0, ebx */
#define EBX7_AVX2     (1u << 5)
#define EBX7_BMI2     (1u << 8)
#define EBX7_AVX512F  (1u << 16)
#define EBX7_SHANI    (1u << 29)
#define EBX7_AVX512VL (1u << 31)

/* XCR0: bit 1 is xmm state, 2 is the ymm halves, 5..7 are the opmask and zmm
   halves. The raw encoding avoids needing the build to allow xgetbv. */
static uint64_t xcr0(void)
{
    uint32_t lo, hi;
    __asm__ volatile(".byte 0x0f, 0x01, 0xd0" : "=a"(lo), "=d"(hi) : "c"(0));
    return ((uint64_t)hi << 32) | lo;
}

static uint32_t detect(void)
{
    uint32_t f = 0, a, b, c, d;

    if (!__get_cpuid(1, &a, &b, &c, &d)) return 0;
    if (d & EDX1_SSE2)   f |= KW_CPU_SSE2;
    if (c & ECX1_SSSE3)  f |= KW_CPU_SSSE3;
    if (c & ECX1_SSE41)  f |= KW_CPU_SSE41;
    if (c & ECX1_AESNI)  f |= KW_CPU_AESNI;
    if (c & ECX1_PCLMUL) f |= KW_CPU_PCLMUL;

    int ymm = 0, zmm = 0;
    if ((c & ECX1_OSXSAVE) && (c & ECX1_AVX)) {
        uint64_t x = xcr0();
        ymm = (x & 0x06) == 0x06;
        zmm = ymm && (x & 0xe0) == 0xe0;
    }
    if (ymm) f |= KW_CPU_AVX;

    if (__get_cpuid_count(7, 0, &a, &b, &c, &d)) {
        if (b & EBX7_BMI2)  f |= KW_CPU_BMI2;
        if (b & EBX7_SHANI) f |= KW_CPU_SHANI;
        if (ymm && (b & EBX7_AVX2)) f |= KW_CPU_AVX2;
        if (zmm && (b & EBX7_AVX512F))  f |= KW_CPU_AVX512F;
        if (zmm && (b & EBX7_AVX512VL)) f |= KW_CPU_AVX512VL;
    }
    return f;
}

#elif defined(__aarch64__) || defined(__arm__)

#if defined(__linux__)
#include <sys/auxv.h>

/* asm/hwcap.h bit numbers, spelled out for the same reason as the CPUID ones */
#if defined(__aarch64__)
#define HW_ASIMD  (1ul << 1)
#define HW_AES    (1ul << 3)
#define HW_PMULL  (1ul << 4)
#define HW_SHA1   (1ul << 5)
#define HW_SHA2   (1ul << 6)
#define HW_CRC32  (1ul << 7)
#define HW_SHA512 (1ul << 21)
#else
#define HW_NEON   (1ul << 12)   /* AT_HWCAP */
#define HW2_AES   (1ul << 0)    /* AT_HWCAP2 */
#define HW2_PMULL (1ul << 1)
#define HW2_SHA1  (1ul << 2)
#define HW2_SHA2  (1ul << 3)
#define HW2_CRC32 (1ul << 4)
#endif

static uint32_t detect(void)
{
    uint32_t f = 0;
    unsigned long h = getauxval(AT_HWCAP);
#if defined(__aarch64__)
    if (h & HW_ASIMD)  f |= KW_CPU_NEON;
    if (h & HW_AES)    f |= KW_CPU_ARM_AES;
    if (h & HW_PMULL)  f |= KW_CPU_PMULL;
    if (h & HW_SHA1)   f |= KW_CPU_SHA1;
    if (h & HW_SHA2)   f |= KW_CPU_SHA2;
    if (h & HW_CRC32)  f |= KW_CPU_CRC32;
    if (h & HW_SHA512) f |= KW_CPU_SHA512;
#else
    unsigned long h2 = getauxval(AT_HWCAP2);
    if (h & HW_NEON)    f |= KW_CPU_NEON;
    if (h2 & HW2_AES)   f |= KW_CPU_ARM_AES;
    if (h2 & HW2_PMULL) f |= KW_CPU_PMULL;
    if (h2 & HW2_SHA1)  f |= KW_CPU_SHA1;
    if (h2 & HW2_SHA2)  f |= KW_CPU_SHA2;
    if (h2 & HW2_CRC32) f |= KW_CPU_CRC32;
#endif
    return f;
}

#elif defined(__APPLE__)
#include <sys/sysctl.h>

/* The FEAT_ keys are recent; where one is missing, fall back to what every arm64
   Mac has, which is the armv8 crypto extensions. */
static int optional(const char *name, int fallback)
{
    int v = 0;
    size_t len = sizeof v;
    if (sysctlbyname(name, &v, &len, NULL, 0) != 0) return fallback;
    return v != 0;
}

static uint32_t detect(void)
{
    uint32_t f = KW_CPU_NEON;
    if (optional("hw.optional.arm.FEAT_AES", 1))    f |= KW_CPU_ARM_AES;
    if (optional("hw.optional.arm.FEAT_PMULL", 1))  f |= KW_CPU_PMULL;
    if (optional("hw.optional.arm.FEAT_SHA1", 1))   f |= KW_CPU_SHA1;
    if (optional("hw.optional.arm.FEAT_SHA256", 1)) f |= KW_CPU_SHA2;
    if (optional("hw.optional.arm.FEAT_SHA512", 0)) f |= KW_CPU_SHA512;
    if (optional("hw.optional.armv8_crc32", 1))     f |= KW_CPU_CRC32;
    return f;
}

#else

/* NEON is architectural on aarch64; nothing else can be asked for portably */
static uint32_t detect(void)
{
#if defined(__aarch64__)
    return KW_CPU_NEON;
#else
    return 0;
#endif
}

#endif

#else

static uint32_t detect(void) { return 0; }

#endif

/* One word, written once. A race detects twice and stores the same value, which
   is why this is not two variables: a separate "done" flag could be seen set
   before the value it guards. */
static uint32_t cache;

uint32_t kw_cpu_features(void)
{
    uint32_t f = cache;
    if (!f) {
        f = detect() | KW_CPU_DETECTED;
        cache = f;
    }
    return f & ~KW_CPU_DETECTED;
}

int kw_cpu_has(uint32_t want)
{
    return (kw_cpu_features() & want) == want;
}

static const struct { uint32_t bit; const char *name; } names[] = {
    { KW_CPU_SSE2, "sse2" },         { KW_CPU_SSSE3, "ssse3" },
    { KW_CPU_SSE41, "sse4_1" },      { KW_CPU_AVX, "avx" },
    { KW_CPU_AVX2, "avx2" },         { KW_CPU_AVX512F, "avx512f" },
    { KW_CPU_AVX512VL, "avx512vl" }, { KW_CPU_SHANI, "sha_ni" },
    { KW_CPU_AESNI, "aesni" },       { KW_CPU_PCLMUL, "pclmulqdq" },
    { KW_CPU_BMI2, "bmi2" },
    { KW_CPU_NEON, "neon" },         { KW_CPU_ARM_AES, "aes" },
    { KW_CPU_PMULL, "pmull" },       { KW_CPU_SHA1, "sha1" },
    { KW_CPU_SHA2, "sha2" },         { KW_CPU_SHA512, "sha512" },
    { KW_CPU_CRC32, "crc32" }
};

char *kw_cpu_summary(char *buf, size_t len)
{
    if (!buf || len == 0) return buf;
    uint32_t f = kw_cpu_features();
    size_t at = 0;
    buf[0] = '\0';
    for (size_t i = 0; i < sizeof names / sizeof *names; i++) {
        if (!(f & names[i].bit)) continue;
        size_t n = 0;
        while (names[i].name[n]) n++;
        if (at + (at ? 1 : 0) + n + 1 > len) break;
        if (at) buf[at++] = ' ';
        for (size_t k = 0; k < n; k++) buf[at + k] = names[i].name[k];
        at += n;
        buf[at] = '\0';
    }
    return buf;
}
