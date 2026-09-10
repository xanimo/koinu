/* koinu.dog - what a spend may pay
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * The size estimate, the two rates, and the ceiling on a fee. Shared because
 * every front end that can sign has to apply the same ceiling: an over-large fee
 * is unrecoverable once the transaction confirms, so a path that skips the check
 * is a way to lose money that the other paths refuse. How a front end reports the
 * refusal is its own business, which is why this returns numbers and prints
 * nothing. */

#ifndef KOINU_FEE_H
#define KOINU_FEE_H

#include <stddef.h>
#include <stdint.h>

/* Dogecoin's minrelaytxfee, the lowest rate a default node will relay, and its
   RECOMMENDED_MIN_TX_FEE, the rate a miner prefers. Both per 1000 bytes. */
#define KW_MIN_RELAY_FEE_PER_KB    100000ULL    /* 0.001 DOGE/kB */
#define KW_RECOMMENDED_FEE_PER_KB 1000000ULL    /* 0.01  DOGE/kB */

/* How many times the recommended fee a spend may pay before it is refused. */
#define KW_MAX_FEE_MULTIPLE 100

/* A signed p2pkh transaction's size: ~148 bytes an input, 34 an output, 10
   overhead. The input estimate rounds up, since a DER signature is 71 or 72
   bytes, so a fee derived from it is never short. */
size_t   kw_est_size(int nin, int nout);
uint64_t kw_est_fee(int nin, int nout, uint64_t rate_per_kb);

/* The most a transaction of (nbytes) may pay: KW_MAX_FEE_MULTIPLE times the
   recommended fee for that size. Scaling by size rather than a flat cap catches
   a mistyped fee on a small spend while leaving a large consolidation room to
   pay what its bytes actually cost. */
uint64_t kw_fee_cap(size_t nbytes);

#endif /* KOINU_FEE_H */
