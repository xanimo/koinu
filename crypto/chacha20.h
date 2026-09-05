/* dogewallet - ChaCha20 (RFC 8439)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#ifndef DOGEWALLET_CHACHA20_H
#define DOGEWALLET_CHACHA20_H

#include <stddef.h>
#include <stdint.h>

#define DW_CHACHA20_KEY   32
#define DW_CHACHA20_NONCE 12

/* One 64-byte keystream block for (key, counter, nonce). */
void dw_chacha20_block(const uint8_t key[DW_CHACHA20_KEY], uint32_t counter,
                       const uint8_t nonce[DW_CHACHA20_NONCE], uint8_t out[64]);

/* XOR (len) bytes of (in) with the keystream starting at (counter). in and out
   may alias. */
void dw_chacha20_xor(const uint8_t key[DW_CHACHA20_KEY], uint32_t counter,
                     const uint8_t nonce[DW_CHACHA20_NONCE],
                     const uint8_t *in, size_t len, uint8_t *out);

#endif /* DOGEWALLET_CHACHA20_H */
