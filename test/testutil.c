/* dogewallet - shared test helpers
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "testutil.h"

#include <stdio.h>
#include <string.h>

static int g_fails = 0;

void dw_test_hex(const uint8_t *b, size_t n, char *out)
{
    static const char *d = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[i*2] = d[b[i] >> 4]; out[i*2+1] = d[b[i] & 15]; }
    out[n*2] = '\0';
}

int dw_test_check(const char *name, const uint8_t *got, size_t n, const char *want)
{
    char h[257];
    if (n > 128) { fprintf(stderr, "FAIL %s: output too long for helper\n", name); g_fails++; return 0; }
    dw_test_hex(got, n, h);
    if (strcmp(h, want) != 0) {
        fprintf(stderr, "FAIL %s\n  got  %s\n  want %s\n", name, h, want);
        g_fails++;
        return 0;
    }
    return 1;
}

int dw_test_fails(void) { return g_fails; }
