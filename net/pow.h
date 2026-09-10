/* koinu.dog - proof of work: compact targets, 256-bit arithmetic, chain work
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * A header's nBits field is a 256-bit target squeezed into 32 bits, and the
 * header's PoW hash has to come out at or below it. Comparing a hash to a target
 * and summing the work a chain represents both need 256-bit integers, which is
 * all this file is besides the two rules.
 *
 * What is here is per-header: this hash against this nBits. What is not here is
 * whether that nBits is the one the chain's own retarget rule demands, which
 * needs the height and the timestamps of the blocks before it, or the floor a
 * network puts under nBits. Both belong with the retarget rules. So this alone
 * proves work was done, not that it was done on the right chain. */

#ifndef KOINU_POW_H
#define KOINU_POW_H

#include <stddef.h>
#include <stdint.h>

/* w[0] is the least significant limb, matching the little-endian byte order the
   rest of the tree calls internal. */
typedef struct { uint32_t w[8]; } kw_u256;

void kw_u256_zero(kw_u256 *a);
void kw_u256_from_bytes(const uint8_t b[32], kw_u256 *out);   /* internal order */
void kw_u256_to_bytes(const kw_u256 *a, uint8_t b[32]);
int  kw_u256_cmp(const kw_u256 *a, const kw_u256 *b);         /* -1, 0, 1 */
int  kw_u256_is_zero(const kw_u256 *a);

/* (acc) += (x). Returns the carry out, which is 1 only if the sum wrapped: a
   caller accumulating chain work wants to know rather than silently continue. */
int  kw_u256_add(kw_u256 *acc, const kw_u256 *x);

/* Decode nBits into a target. Returns 0 if the encoding is negative, overflows
   256 bits, or encodes zero, none of which is a usable target. */
int  kw_bits_target(uint32_t bits, kw_u256 *out);

/* Re-encode a target, which is lossy: the result is the largest compact value
   not above (t). kw_bits_target of the result round-trips for any (bits) that
   was itself canonical. */
uint32_t kw_target_bits(const kw_u256 *t);

/* The work a target represents, 2^256 / (target + 1), which is the expected
   number of hashes to meet it. Summed over a chain this is the quantity that
   decides which of two chains is the most work. Returns 0 if (bits) is not a
   usable target. */
int  kw_bits_work(uint32_t bits, kw_u256 *out);

/* 1 if (pow_hash), in internal byte order, is at or below the target (bits)
   encodes. 0 if it is above, or if (bits) is not a usable target. */
int  kw_pow_check(const uint8_t pow_hash[32], uint32_t bits);

/* nBits out of an 80-byte header, which is bytes 72..75 little-endian. */
uint32_t kw_header_bits(const uint8_t header[80]);

#endif /* KOINU_POW_H */
