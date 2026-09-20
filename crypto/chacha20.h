/* koinu.dog - ChaCha20 (RFC 8439)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#ifndef KOINU_CHACHA20_H
#define KOINU_CHACHA20_H

#include <stddef.h>
#include <stdint.h>

#define KW_CHACHA20_KEY   32
#define KW_CHACHA20_NONCE 12

/* One 64-byte keystream block for (key, counter, nonce). */
void kw_chacha20_block(const uint8_t key[KW_CHACHA20_KEY], uint32_t counter,
                       const uint8_t nonce[KW_CHACHA20_NONCE], uint8_t out[64]);

/* XOR (len) bytes of (in) with the keystream starting at (counter). in and out
   may alias. Returns 0 without writing anything if len would run the 32-bit
   counter past its end, since a wrapped counter repeats the keystream. */
int kw_chacha20_xor(const uint8_t key[KW_CHACHA20_KEY], uint32_t counter,
                     const uint8_t nonce[KW_CHACHA20_NONCE],
                     const uint8_t *in, size_t len, uint8_t *out);

#endif /* KOINU_CHACHA20_H */
