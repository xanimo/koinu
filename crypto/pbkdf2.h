/* dogewallet - PBKDF2-HMAC-SHA512 (RFC 8018)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#ifndef DOGEWALLET_PBKDF2_H
#define DOGEWALLET_PBKDF2_H

#include <stddef.h>
#include <stdint.h>

/* Derive (outlen) bytes from (pass) and (salt) with (iterations) rounds of
   HMAC-SHA512. This is the KDF BIP39 mandates for mnemonic-to-seed (salt
   "mnemonic"+passphrase, 2048 rounds, 64-byte output). Returns 1 on success,
   0 on a bad argument. */
int dw_pbkdf2_hmac_sha512(const uint8_t *pass, size_t passlen,
                          const uint8_t *salt, size_t saltlen,
                          uint32_t iterations,
                          uint8_t *out, size_t outlen);

#endif /* DOGEWALLET_PBKDF2_H */
