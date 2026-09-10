/* koinu.dog - what a spend may pay
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "fee.h"

size_t kw_est_size(int nin, int nout)
{
    if (nin < 0) nin = 0;
    if (nout < 0) nout = 0;
    return 10 + 148u * (size_t)nin + 34u * (size_t)nout;
}

uint64_t kw_est_fee(int nin, int nout, uint64_t rate_per_kb)
{
    return ((uint64_t)kw_est_size(nin, nout) * rate_per_kb + 999) / 1000;   /* round up */
}

uint64_t kw_fee_cap(size_t nbytes)
{
    return ((uint64_t)nbytes * KW_RECOMMENDED_FEE_PER_KB + 999) / 1000 * KW_MAX_FEE_MULTIPLE;
}
