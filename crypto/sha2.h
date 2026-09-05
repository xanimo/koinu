/* dogewallet - SHA-256 and SHA-512 (FIPS 180-4)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#ifndef DOGEWALLET_SHA2_H
#define DOGEWALLET_SHA2_H

#include <stddef.h>
#include <stdint.h>

#define DW_SHA256_LEN 32
#define DW_SHA512_LEN 64
#define DW_SHA256_BLOCK 64
#define DW_SHA512_BLOCK 128

typedef struct {
    uint32_t h[8];
    uint64_t bits;                 /* message length in bits, mod 2^64 */
    uint8_t  buf[DW_SHA256_BLOCK];
    size_t   n;                    /* bytes buffered, < DW_SHA256_BLOCK */
} dw_sha256_ctx;

void dw_sha256_init(dw_sha256_ctx *c);
void dw_sha256_update(dw_sha256_ctx *c, const void *data, size_t len);
void dw_sha256_final(dw_sha256_ctx *c, uint8_t out[DW_SHA256_LEN]);
void dw_sha256(const void *data, size_t len, uint8_t out[DW_SHA256_LEN]);

/* Bitcoin's hash256: SHA-256 applied twice. */
void dw_hash256(const void *data, size_t len, uint8_t out[DW_SHA256_LEN]);

typedef struct {
    uint64_t h[8];
    uint64_t bits_hi, bits_lo;     /* 128-bit message length in bits */
    uint8_t  buf[DW_SHA512_BLOCK];
    size_t   n;
} dw_sha512_ctx;

void dw_sha512_init(dw_sha512_ctx *c);
void dw_sha512_update(dw_sha512_ctx *c, const void *data, size_t len);
void dw_sha512_final(dw_sha512_ctx *c, uint8_t out[DW_SHA512_LEN]);
void dw_sha512(const void *data, size_t len, uint8_t out[DW_SHA512_LEN]);

#endif /* DOGEWALLET_SHA2_H */
