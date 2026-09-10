/* koinu.dog - the scalar scrypt core, under a second set of names
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Compiles crypto/scrypt.c a second time with the SIMD cores switched off, so
 * one test binary holds both and can check that the vector Salsa20/8 agrees
 * with the scalar one on this machine. A wrong lane or shuffle constant passes
 * a self-consistency check and fails here. */

#define KW_SCRYPT_PORTABLE
#define kw_scrypt            kw_scrypt_portable
#define kw_scrypt_pow        kw_scrypt_pow_portable
#define kw_scrypt_pow_batch  kw_scrypt_pow_batch_portable
#define kw_scrypt_backend    kw_scrypt_backend_portable
#define kw_scrypt_batch_backend kw_scrypt_batch_backend_portable

#include "../crypto/scrypt.c"
