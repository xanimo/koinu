/* koinu.dog - proof of work: compact targets, 256-bit arithmetic, chain work
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * A header's nBits field is a 256-bit target squeezed into 32 bits, and the
 * header's PoW hash has to come out at or below it. Comparing a hash to a target
 * and summing the work a chain represents both need 256-bit integers, which is
 * all this file is besides the two rules.
 *
 * The retarget rule is here too: what nBits the chain demands at a height, which
 * is what turns "work was done" into "work was done on this chain". Dogecoin has
 * two regimes, a Litecoin-style 240-block period before height 145000 and
 * DigiShield every block from 145001, and the switch is not one condition: the
 * timespan and the damping come from the height being validated while the period
 * length comes from the height before it. Mainnet only, since testnet and regtest
 * permit minimum-difficulty blocks, which needs a walk back to the last block that
 * was not one.
 *
 * Still not here: AuxPoW. A merged-mined block's work is proved by its parent, and
 * nothing in this file looks at the parent. */

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

/* nBits out of an 80-byte header, which is bytes 72..75 little-endian, and the
   timestamp, which is bytes 68..71. */
uint32_t kw_header_bits(const uint8_t header[80]);
uint32_t kw_header_time(const uint8_t header[80]);

/* ── the retarget rule ─────────────────────────────────────────────────── */

typedef struct {
    uint32_t digishield_height;  /* the first height whose period is one block */
    uint32_t powlimit_bits;      /* the easiest target the chain will accept */
    int32_t  timespan_pre;       /* seconds a period should take, before and after */
    int32_t  timespan_post;
    int32_t  spacing;            /* seconds a block should take */
} kw_pow_rules;

extern const kw_pow_rules KW_POW_MAIN;

/* Does the block at (height) recompute its target, and if so which earlier
   block's timestamp does the computation need? Returns 1 and sets *first_height,
   or 0 when the block simply carries the previous block's nBits. */
int kw_pow_retargets(const kw_pow_rules *r, uint32_t height, uint32_t *first_height);

/* The nBits the rule demands at (height), given the previous block's bits and
   time and the timestamp of the block kw_pow_retargets named. When it does not
   retarget this returns (last_bits), so it can be called at every height. */
uint32_t kw_pow_next_bits(const kw_pow_rules *r, uint32_t height, uint32_t last_bits,
                          uint32_t last_time, uint32_t first_time);

#endif /* KOINU_POW_H */
