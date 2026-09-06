/* koinu.dog - RIPEMD-160
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#ifndef KOINU_RIPEMD160_H
#define KOINU_RIPEMD160_H

#include <stddef.h>
#include <stdint.h>

#define KW_RIPEMD160_LEN 20
#define KW_RIPEMD160_BLOCK 64

typedef struct {
    uint32_t h[5];
    uint64_t bits;                    /* message length in bits, mod 2^64 */
    uint8_t  buf[KW_RIPEMD160_BLOCK];
    size_t   n;
} kw_ripemd160_ctx;

void kw_ripemd160_init(kw_ripemd160_ctx *c);
void kw_ripemd160_update(kw_ripemd160_ctx *c, const void *data, size_t len);
void kw_ripemd160_final(kw_ripemd160_ctx *c, uint8_t out[KW_RIPEMD160_LEN]);
void kw_ripemd160(const void *data, size_t len, uint8_t out[KW_RIPEMD160_LEN]);

/* Bitcoin's hash160: RIPEMD-160 of SHA-256, the script/address hash. */
void kw_hash160(const void *data, size_t len, uint8_t out[KW_RIPEMD160_LEN]);

#endif /* KOINU_RIPEMD160_H */
