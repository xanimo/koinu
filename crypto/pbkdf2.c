/* koinu.dog - PBKDF2-HMAC-SHA256/512 (RFC 8018)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * T_i = U_1 xor U_2 xor ... xor U_c, with U_1 = PRF(pass, salt || INT32BE(i))
 * and U_k = PRF(pass, U_{k-1}). The SHA512 form is what BIP39 mandates for
 * mnemonic-to-seed; the SHA256 form is scrypt's PRF. Verified against the
 * canonical BIP39 seed and the RFC 6070 vectors in test/test_pbkdf2.c. */

#include "pbkdf2.h"
#include "hmac.h"
#include "mem.h"

#include <stdlib.h>
#include <string.h>

#define HLEN KW_SHA512_LEN   /* 64 */

int kw_pbkdf2_hmac_sha512(const uint8_t *pass, size_t passlen,
                          const uint8_t *salt, size_t saltlen,
                          uint32_t iterations,
                          uint8_t *out, size_t outlen)
{
    if (iterations == 0 || (outlen && !out)) return 0;

    /* scratch = salt || INT32BE(block). The salt is not secret, but we free it
       clean anyway. Heap because the salt length is caller-chosen. */
    uint8_t *scratch = (uint8_t *)malloc(saltlen + 4);
    if (!scratch) return 0;
    memcpy(scratch, salt, saltlen);

    uint8_t U[HLEN], T[HLEN];
    size_t off = 0;
    uint32_t block = 1;

    while (off < outlen) {
        scratch[saltlen + 0] = (uint8_t)(block >> 24);
        scratch[saltlen + 1] = (uint8_t)(block >> 16);
        scratch[saltlen + 2] = (uint8_t)(block >> 8);
        scratch[saltlen + 3] = (uint8_t)(block);

        kw_hmac_sha512(pass, passlen, scratch, saltlen + 4, U);
        memcpy(T, U, HLEN);
        for (uint32_t j = 1; j < iterations; j++) {
            kw_hmac_sha512(pass, passlen, U, HLEN, U);
            for (size_t k = 0; k < HLEN; k++) T[k] ^= U[k];
        }

        size_t take = outlen - off < HLEN ? outlen - off : HLEN;
        memcpy(out + off, T, take);
        off += take;
        block++;
    }

    kw_secure_zero(U, sizeof U);
    kw_secure_zero(T, sizeof T);
    kw_secure_zero(scratch, saltlen + 4);
    free(scratch);
    return 1;
}

int kw_pbkdf2_hmac_sha256(const uint8_t *pass, size_t passlen,
                          const uint8_t *salt, size_t saltlen,
                          uint32_t iterations,
                          uint8_t *out, size_t outlen)
{
    if (iterations == 0 || (outlen && !out)) return 0;

    uint8_t *scratch = (uint8_t *)malloc(saltlen + 4);
    if (!scratch) return 0;
    memcpy(scratch, salt, saltlen);

    uint8_t U[KW_SHA256_LEN], T[KW_SHA256_LEN];
    size_t off = 0;
    uint32_t block = 1;

    while (off < outlen) {
        scratch[saltlen + 0] = (uint8_t)(block >> 24);
        scratch[saltlen + 1] = (uint8_t)(block >> 16);
        scratch[saltlen + 2] = (uint8_t)(block >> 8);
        scratch[saltlen + 3] = (uint8_t)(block);

        kw_hmac_sha256(pass, passlen, scratch, saltlen + 4, U);
        memcpy(T, U, sizeof T);
        for (uint32_t j = 1; j < iterations; j++) {
            kw_hmac_sha256(pass, passlen, U, sizeof U, U);
            for (size_t k = 0; k < sizeof T; k++) T[k] ^= U[k];
        }

        size_t take = outlen - off < sizeof T ? outlen - off : sizeof T;
        memcpy(out + off, T, take);
        off += take;
        block++;
    }

    kw_secure_zero(U, sizeof U);
    kw_secure_zero(T, sizeof T);
    kw_secure_zero(scratch, saltlen + 4);
    free(scratch);
    return 1;
}
