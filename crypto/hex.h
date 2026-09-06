/* koinu.dog - hex encode/decode
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#ifndef KOINU_HEX_H
#define KOINU_HEX_H

#include <stddef.h>
#include <stdint.h>

/* Lowercase-hex encode (inlen) bytes into (out), NUL-terminated. Returns the
   string length (2*inlen), or 0 if (out) cannot hold 2*inlen+1. */
size_t kw_hex_encode(const uint8_t *in, size_t inlen, char *out, size_t outcap);

/* Decode exactly (outlen) bytes from (hexlen) hex chars. Returns 1 on success,
   0 on a length mismatch or a non-hex character. */
int kw_hex_decode(const char *hex, size_t hexlen, uint8_t *out, size_t outlen);

#endif /* KOINU_HEX_H */
