/* koinu.dog - fee policy tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * The numbers two front ends now share. test/test_sweep.sh checks that kw refuses
 * an absurd fee end to end; this pins the arithmetic underneath it, so a change
 * to the ceiling has to be deliberate rather than a rounding accident. kwui has
 * no end-to-end test, which makes this the only check on its side. */

#include "fee.h"

#include <stdio.h>

static int fail;

static void eq(const char *what, uint64_t got, uint64_t want)
{
    if (got != want) {
        fprintf(stderr, "FAIL: %s: got %llu, want %llu\n", what,
                (unsigned long long)got, (unsigned long long)want);
        fail = 1;
    }
}

int main(void)
{
    /* 10 overhead, 148 an input, 34 an output */
    eq("size 1 in 1 out", kw_est_size(1, 1), 192);
    eq("size 1 in 2 out", kw_est_size(1, 2), 226);
    eq("size 8 in 2 out", kw_est_size(8, 2), 1262);

    /* at the relay rate, which is what a spend pays unless told otherwise */
    eq("fee 1 in 1 out", kw_est_fee(1, 1, KW_MIN_RELAY_FEE_PER_KB), 19200);
    eq("fee 1 in 2 out", kw_est_fee(1, 2, KW_MIN_RELAY_FEE_PER_KB), 22600);

    /* a fee is rounded up, never down: a spend short of the relay rate does not
       relay, and 0.192 of a koinu is still a koinu */
    eq("rounds up", kw_est_fee(1, 1, 1), 1);
    eq("rounds up, not to zero", kw_est_fee(0, 0, 1), 1);

    /* the ceiling: 100x the recommended rate for the size */
    eq("cap 226 bytes", kw_fee_cap(226), 22600000);
    eq("cap 192 bytes", kw_fee_cap(192), 19200000);

    /* the relay-rate fee for a transaction is always inside its own ceiling, or
       every default spend would be refused */
    for (int nin = 1; nin <= 64; nin++)
        for (int nout = 1; nout <= 2; nout++) {
            size_t n = kw_est_size(nin, nout);
            if (kw_est_fee(nin, nout, KW_MIN_RELAY_FEE_PER_KB) > kw_fee_cap(n)) {
                fprintf(stderr, "FAIL: %d in %d out is refused by default\n", nin, nout);
                fail = 1;
            }
        }

    /* the ceiling rises with size, so a consolidation is not held to a small
       spend's limit */
    if (kw_fee_cap(kw_est_size(64, 2)) <= kw_fee_cap(kw_est_size(1, 2)))
        { fprintf(stderr, "FAIL: the cap does not scale with size\n"); fail = 1; }

    /* a negative count cannot shrink the estimate below the overhead */
    eq("negative inputs", kw_est_size(-5, 1), 44);

    if (fail) return 1;
    printf("fee ok: sizes, relay-rate fees, rounding up, the 100x ceiling,\n"
           "  every default spend inside its own ceiling for 1..64 inputs\n");
    return 0;
}
