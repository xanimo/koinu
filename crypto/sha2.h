/* koinu.dog - SHA-256 and SHA-512 (FIPS 180-4)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#ifndef KOINU_SHA2_H
#define KOINU_SHA2_H

#include <stddef.h>
#include <stdint.h>

#define KW_SHA256_LEN 32
#define KW_SHA512_LEN 64
#define KW_SHA256_BLOCK 64
#define KW_SHA512_BLOCK 128

typedef struct {
    uint32_t h[8];
    uint64_t bits;                 /* message length in bits, mod 2^64 */
    uint8_t  buf[KW_SHA256_BLOCK];
    size_t   n;                    /* bytes buffered, < KW_SHA256_BLOCK */
} kw_sha256_ctx;

void kw_sha256_init(kw_sha256_ctx *c);
void kw_sha256_update(kw_sha256_ctx *c, const void *data, size_t len);
void kw_sha256_final(kw_sha256_ctx *c, uint8_t out[KW_SHA256_LEN]);
void kw_sha256(const void *data, size_t len, uint8_t out[KW_SHA256_LEN]);

/* One compression, exposed so a validator can drive it directly and so the hardware
   cores can be held against this one. (h) is the eight-word state, updated in place;
   (p) is one 64-byte block. kw_sha256_compress dispatches; _scalar never does. */
void kw_sha256_compress(uint32_t h[8], const uint8_t *p);
void kw_sha256_compress_scalar(uint32_t h[8], const uint8_t *p);

/* The SHA-256 instructions, where the CPU has them and they agree with the scalar
   core on a known block. A core that disagrees is refused: see crypto/sha2_hw.c. */
int         kw_sha256_hw(void);
void        kw_sha256_compress_hw(uint32_t h[8], const uint8_t *p);
const char *kw_sha256_backend(void);

/* Bitcoin's hash256: SHA-256 applied twice. */
void kw_hash256(const void *data, size_t len, uint8_t out[KW_SHA256_LEN]);

typedef struct {
    uint64_t h[8];
    uint64_t bits_hi, bits_lo;     /* 128-bit message length in bits */
    uint8_t  buf[KW_SHA512_BLOCK];
    size_t   n;
} kw_sha512_ctx;

void kw_sha512_init(kw_sha512_ctx *c);
void kw_sha512_update(kw_sha512_ctx *c, const void *data, size_t len);
void kw_sha512_final(kw_sha512_ctx *c, uint8_t out[KW_SHA512_LEN]);
void kw_sha512(const void *data, size_t len, uint8_t out[KW_SHA512_LEN]);

#endif /* KOINU_SHA2_H */
