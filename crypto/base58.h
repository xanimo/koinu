/* koinu.dog - base58 and base58check
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#ifndef KOINU_BASE58_H
#define KOINU_BASE58_H

#include <stddef.h>
#include <stdint.h>

/* Encode (in) as base58 into (out), NUL-terminated. Returns the string length,
   or 0 on failure (including (out) too small). */
size_t kw_base58_encode(const uint8_t *in, size_t inlen, char *out, size_t outcap);

/* Decode a base58 string into (out). Returns 1 on success with the byte length
   in (outlen), 0 on an invalid character or (out) too small. */
int kw_base58_decode(const char *in, uint8_t *out, size_t outcap, size_t *outlen);

/* base58check: append a 4-byte double-SHA256 checksum, then base58. */
size_t kw_base58check_encode(const uint8_t *payload, size_t len, char *out, size_t outcap);

/* Decode and verify the checksum, returning only the payload. Returns 1 on
   success, 0 on a bad character, a bad checksum, or (out) too small. */
int kw_base58check_decode(const char *in, uint8_t *out, size_t outcap, size_t *outlen);

#endif /* KOINU_BASE58_H */
