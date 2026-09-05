/* dogewallet - shared test helpers
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "testutil.h"
#include "hex.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails = 0;

size_t dw_test_unhex(const char *hex, uint8_t *out)
{
    size_t hexlen = strlen(hex);
    size_t n = hexlen / 2;
    if (!dw_hex_decode(hex, hexlen, out, n)) {
        fprintf(stderr, "test bug: malformed hex literal\n");
        abort();
    }
    return n;
}

int dw_test_check(const char *name, const uint8_t *got, size_t n, const char *want)
{
    char h[513];
    if (n > 256) { fprintf(stderr, "FAIL %s: output too long for helper\n", name); g_fails++; return 0; }
    dw_hex_encode(got, n, h, sizeof h);
    if (strcmp(h, want) != 0) {
        fprintf(stderr, "FAIL %s\n  got  %s\n  want %s\n", name, h, want);
        g_fails++;
        return 0;
    }
    return 1;
}

int dw_test_fails(void) { return g_fails; }
