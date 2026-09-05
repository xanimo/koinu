/* dogewallet - encrypted keystore
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Seal a secret (a seed or master key) under a passphrase: argon2id stretches
 * the passphrase, chacha20-poly1305 encrypts, and the header (version, kdf
 * params, salt, nonce) is authenticated as associated data so none of it can be
 * altered without failing the tag. Bytes in, bytes out; the caller owns the
 * file. Open is fail-closed: a wrong passphrase or any tampering yields nothing. */

#ifndef DOGEWALLET_KEYSTORE_H
#define DOGEWALLET_KEYSTORE_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t t_cost;        /* argon2 passes            */
    uint32_t m_cost_kib;    /* argon2 memory, KiB       */
    uint32_t parallelism;   /* argon2 lanes             */
} dw_keystore_params;

/* Interactive defaults: 3 passes over 64 MiB, one lane. */
extern const dw_keystore_params DW_KEYSTORE_DEFAULT;

#define DW_KEYSTORE_MAX_SECRET 4096

/* Serialized size for a secret of (secretlen): header + ciphertext + tag. */
size_t dw_keystore_sealed_size(size_t secretlen);

/* Seal (secret) under (passphrase). Writes the serialized keystore to (out) and
   returns its length, or 0 on a bad argument, RNG failure, or (out) too small.
   A fresh random salt and nonce are drawn each call. */
size_t dw_keystore_seal(const uint8_t *secret, size_t secretlen,
                        const char *passphrase,
                        const dw_keystore_params *params,
                        uint8_t *out, size_t outcap);

/* Open a keystore. Returns 1 and writes the secret to (out) with its length in
   (secretlen) only on the right passphrase and intact data; otherwise returns 0
   and leaves nothing usable in (out). */
int dw_keystore_open(const uint8_t *blob, size_t bloblen,
                     const char *passphrase,
                     uint8_t *out, size_t outcap, size_t *secretlen);

#endif /* DOGEWALLET_KEYSTORE_H */
