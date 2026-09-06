/* koinu.dog - Argon2id tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Vector from the argon2 reference test suite (v=19, argon2id). */

#include "kdf.h"
#include "testutil.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    uint8_t out[32];

    /* PHC argon2id vector: t=2, m=65536 KiB, p=1, "password" / "somesalt" */
    if (!kw_argon2id((const uint8_t *)"password", 8, (const uint8_t *)"somesalt", 8,
                     2, 65536, 1, out, sizeof out)) {
        fprintf(stderr, "FAIL: argon2id returned error\n"); return 1;
    }
    kw_test_check("argon2id t=2 m=65536 p=1", out, 32,
        "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7");

    /* determinism, and that the cost parameters actually change the output */
    uint8_t again[32], other[32];
    kw_argon2id((const uint8_t *)"password", 8, (const uint8_t *)"somesalt", 8, 2, 65536, 1, again, 32);
    if (memcmp(out, again, 32) != 0) { fprintf(stderr, "FAIL: not deterministic\n"); return 1; }
    kw_argon2id((const uint8_t *)"password", 8, (const uint8_t *)"somesalt", 8, 3, 65536, 1, other, 32);
    if (memcmp(out, other, 32) == 0) { fprintf(stderr, "FAIL: t_cost had no effect\n"); return 1; }

    if (kw_test_fails()) { fprintf(stderr, "%d argon2 case(s) failed\n", kw_test_fails()); return 1; }
    printf("argon2 ok: phc argon2id vector, determinism, and t_cost sensitivity\n");
    return 0;
}
