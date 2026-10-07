/* koinu.dog - what a spend may pay
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "fee.h"

#include <stdint.h>

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

int kw_parse_doge(const char *s, uint64_t *out)
{
    if (!s) return 0;
    uint64_t whole = 0, frac = 0;
    int digits = 0, seen = 0;
    const char *p = s;
    for (; *p && *p != '.'; p++) {
        if (*p < '0' || *p > '9') return 0;
        if (whole > (UINT64_MAX - 9) / 10) return 0;
        whole = whole * 10 + (uint64_t)(*p - '0'); seen = 1;
    }
    if (*p == '.') for (p++; *p; p++) {
        if (*p < '0' || *p > '9') return 0;
        if (digits == 8) return 0;
        frac = frac * 10 + (uint64_t)(*p - '0'); digits++; seen = 1;
    }
    if (!seen) return 0;
    while (digits++ < 8) frac *= 10;
    if (whole > KOINU_MAX_MONEY / 100000000ULL) return 0;
    uint64_t v = whole * 100000000ULL;
    if (v > KOINU_MAX_MONEY - frac) return 0;
    *out = v + frac;
    return 1;
}
