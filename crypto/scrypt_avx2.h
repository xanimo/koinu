/* koinu.dog - the eight-at-once scrypt core, AVX2
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Only the r=1 ROMix, which is the whole of Dogecoin's PoW hash bar two PBKDF2
 * calls. The core is compiled in on x86_64 whatever the build's -m flags, since
 * the AVX2 functions carry their own target attribute, and selected at run time
 * by kw_scrypt_avx2_available(). Callers go through crypto/scrypt.h. */

#ifndef KOINU_SCRYPT_AVX2_H
#define KOINU_SCRYPT_AVX2_H

#include <stdint.h>

#if defined(__x86_64__)
#define KW_SCRYPT_AVX2 1

/* 1 if this CPU has AVX2. Cached after the first call. */
int kw_scrypt_avx2_available(void);

/* ROMix at r=1 over eight independent states. X[l] is state l's 32 words in and
   out, V[l] its 128*n byte scratchpad, (n) a power of two. */
void kw_scrypt_romix8_avx2(uint32_t X[8][32], uint32_t *const V[8], uint64_t n);
#endif

#endif /* KOINU_SCRYPT_AVX2_H */
