/* dogewallet - RIPEMD-160
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#ifndef DOGEWALLET_RIPEMD160_H
#define DOGEWALLET_RIPEMD160_H

#include <stddef.h>
#include <stdint.h>

#define DW_RIPEMD160_LEN 20
#define DW_RIPEMD160_BLOCK 64

typedef struct {
    uint32_t h[5];
    uint64_t bits;                    /* message length in bits, mod 2^64 */
    uint8_t  buf[DW_RIPEMD160_BLOCK];
    size_t   n;
} dw_ripemd160_ctx;

void dw_ripemd160_init(dw_ripemd160_ctx *c);
void dw_ripemd160_update(dw_ripemd160_ctx *c, const void *data, size_t len);
void dw_ripemd160_final(dw_ripemd160_ctx *c, uint8_t out[DW_RIPEMD160_LEN]);
void dw_ripemd160(const void *data, size_t len, uint8_t out[DW_RIPEMD160_LEN]);

/* Bitcoin's hash160: RIPEMD-160 of SHA-256, the script/address hash. */
void dw_hash160(const void *data, size_t len, uint8_t out[DW_RIPEMD160_LEN]);

#endif /* DOGEWALLET_RIPEMD160_H */
