/* koinu.dog - Argon2id key derivation
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#ifndef KOINU_KDF_H
#define KOINU_KDF_H

#include <stddef.h>
#include <stdint.h>

/* Argon2id: derive (outlen) bytes from (pass) and (salt). t_cost is passes,
   m_cost is memory in KiB, parallelism is lanes. Thin wrapper over the vendored
   argon2 reference; returns 1 on success, 0 on any argon2 error. This is the
   memory-hard KDF for the at-rest keystore, distinct from PBKDF2 which BIP39
   mandates for mnemonic-to-seed. */
int kw_argon2id(const uint8_t *pass, size_t passlen,
                const uint8_t *salt, size_t saltlen,
                uint32_t t_cost, uint32_t m_cost_kib, uint32_t parallelism,
                uint8_t *out, size_t outlen);

#endif /* KOINU_KDF_H */
