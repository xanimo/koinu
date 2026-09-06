/* koinu.dog - SipHash-2-4
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * The keyed PRF BIP158 uses to place each element in the Golomb-coded set. The
 * key is 16 bytes read as two little-endian 64-bit words (k0, k1). */

#ifndef KOINU_SIPHASH_H
#define KOINU_SIPHASH_H

#include <stddef.h>
#include <stdint.h>

uint64_t kw_siphash24(const uint8_t key[16], const uint8_t *data, size_t len);

#endif /* KOINU_SIPHASH_H */
