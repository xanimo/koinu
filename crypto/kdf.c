/* dogewallet - Argon2id key derivation
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "kdf.h"

#include "argon2.h"

int dw_argon2id(const uint8_t *pass, size_t passlen,
                const uint8_t *salt, size_t saltlen,
                uint32_t t_cost, uint32_t m_cost_kib, uint32_t parallelism,
                uint8_t *out, size_t outlen)
{
    int r = argon2id_hash_raw(t_cost, m_cost_kib, parallelism,
                              pass, passlen, salt, saltlen, out, outlen);
    return r == ARGON2_OK;
}
