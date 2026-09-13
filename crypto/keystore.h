/* koinu.dog - encrypted keystore
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Seal a secret (a seed or master key) under a passphrase: argon2id stretches
 * the passphrase, chacha20-poly1305 encrypts, and the header (version, kdf
 * params, salt, nonce) is authenticated as associated data so none of it can be
 * altered without failing the tag. Bytes in, bytes out; the caller owns the
 * file. Open is fail-closed: a wrong passphrase or any tampering yields nothing. */

#ifndef KOINU_KEYSTORE_H
#define KOINU_KEYSTORE_H

#include <stddef.h>
#include <stdint.h>

/* Bounds on the KDF parameters a keystore may ask for. They are read out of the file
   header and drive argon2 before the tag can be checked, so authentication cannot
   help: a tampered t_cost is a uint32 and turns opening a wallet into a hang of years.
   Generous against the defaults of 3 passes and 64 MiB, so raising them later needs no
   change here. */
#define KW_KEYSTORE_MAX_T_COST      32
#define KW_KEYSTORE_MAX_M_COST_KIB  (1u << 20)   /* 1 GiB */
#define KW_KEYSTORE_MAX_PARALLELISM 8

typedef struct {
    uint32_t t_cost;        /* argon2 passes            */
    uint32_t m_cost_kib;    /* argon2 memory, KiB       */
    uint32_t parallelism;   /* argon2 lanes             */
} kw_keystore_params;

/* Interactive defaults: 3 passes over 64 MiB, one lane. */
extern const kw_keystore_params KW_KEYSTORE_DEFAULT;

#define KW_KEYSTORE_MAX_SECRET 4096

/* Serialized size for a secret of (secretlen): header + ciphertext + tag. */
size_t kw_keystore_sealed_size(size_t secretlen);

/* Seal (secret) under (passphrase). Writes the serialized keystore to (out) and
   returns its length, or 0 on a bad argument, RNG failure, or (out) too small.
   A fresh random salt and nonce are drawn each call. */
size_t kw_keystore_seal(const uint8_t *secret, size_t secretlen,
                        const char *passphrase,
                        const kw_keystore_params *params,
                        uint8_t *out, size_t outcap);

/* Open a keystore. Returns 1 and writes the secret to (out) with its length in
   (secretlen) only on the right passphrase and intact data; otherwise returns 0
   and leaves nothing usable in (out). */
int kw_keystore_open(const uint8_t *blob, size_t bloblen,
                     const char *passphrase,
                     uint8_t *out, size_t outcap, size_t *secretlen);

#endif /* KOINU_KEYSTORE_H */
