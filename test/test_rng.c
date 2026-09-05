/* dogewallet - rng and secure-mem sanity
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "rng.h"
#include "mem.h"

#include <stdio.h>
#include <string.h>

static int all_zero(const unsigned char *b, size_t n)
{
    unsigned char acc = 0;
    for (size_t i = 0; i < n; i++) acc |= b[i];
    return acc == 0;
}

int main(void)
{
    unsigned char a[64], b[64];

    if (!dw_random_bytes(a, sizeof a)) { fprintf(stderr, "FAIL: rng failed\n"); return 1; }
    if (all_zero(a, sizeof a))         { fprintf(stderr, "FAIL: all zero draw\n"); return 1; }
    if (!dw_random_bytes(b, sizeof b)) { fprintf(stderr, "FAIL: rng failed (2)\n"); return 1; }
    if (!memcmp(a, b, sizeof a))       { fprintf(stderr, "FAIL: two draws identical\n"); return 1; }
    if (!dw_random_selftest())         { fprintf(stderr, "FAIL: selftest\n"); return 1; }

    unsigned char s[16];
    memcpy(s, "secretsecret!!!!", 16);
    dw_secure_zero(s, sizeof s);
    if (!all_zero(s, sizeof s))        { fprintf(stderr, "FAIL: secure_zero\n"); return 1; }

    unsigned char x[4] = {1, 2, 3, 4}, y[4] = {1, 2, 3, 4}, z[4] = {1, 2, 3, 5};
    if (dw_memeq_ct(x, y, 4) != 0)     { fprintf(stderr, "FAIL: ct compare equal\n"); return 1; }
    if (dw_memeq_ct(x, z, 4) == 0)     { fprintf(stderr, "FAIL: ct compare differ\n"); return 1; }

    printf("rng ok: 64-byte draws differ, selftest passed, secure_zero and ct-compare ok\n");
    return 0;
}
