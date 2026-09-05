/* dogewallet - shared test helpers
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#ifndef DOGEWALLET_TESTUTIL_H
#define DOGEWALLET_TESTUTIL_H

#include <stddef.h>
#include <stdint.h>

/* Hex-encode (n) bytes into (out), which must hold 2*n+1 chars including NUL. */
void dw_test_hex(const uint8_t *b, size_t n, char *out);

/* Compare (got,n) against the hex string (want). On mismatch, prints a labelled
   diff and records a failure. Returns 1 on match, 0 otherwise. */
int dw_test_check(const char *name, const uint8_t *got, size_t n, const char *want);

/* How many checks have failed so far, for main() to return on. */
int dw_test_fails(void);

#endif /* DOGEWALLET_TESTUTIL_H */
