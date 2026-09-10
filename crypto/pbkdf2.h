/* koinu.dog - PBKDF2-HMAC-SHA256/512 (RFC 8018)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#ifndef KOINU_PBKDF2_H
#define KOINU_PBKDF2_H

#include <stddef.h>
#include <stdint.h>

/* Derive (outlen) bytes from (pass) and (salt) with (iterations) rounds of
   HMAC-SHA512. This is the KDF BIP39 mandates for mnemonic-to-seed (salt
   "mnemonic"+passphrase, 2048 rounds, 64-byte output). Returns 1 on success,
   0 on a bad argument. */
int kw_pbkdf2_hmac_sha512(const uint8_t *pass, size_t passlen,
                          const uint8_t *salt, size_t saltlen,
                          uint32_t iterations,
                          uint8_t *out, size_t outlen);

/* The same over HMAC-SHA256, which is what scrypt's PRF is (RFC 7914). */
int kw_pbkdf2_hmac_sha256(const uint8_t *pass, size_t passlen,
                          const uint8_t *salt, size_t saltlen,
                          uint32_t iterations,
                          uint8_t *out, size_t outlen);

#endif /* KOINU_PBKDF2_H */
