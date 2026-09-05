/* dogewallet - ChaCha20-Poly1305 AEAD (RFC 8439)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#ifndef DOGEWALLET_AEAD_H
#define DOGEWALLET_AEAD_H

#include <stddef.h>
#include <stdint.h>

#define DW_AEAD_KEY   32
#define DW_AEAD_NONCE 12
#define DW_AEAD_TAG   16

/* Encrypt (pt) into (ct) (same length; may alias) and write the authentication
   tag over (aad)+ciphertext. */
void dw_chacha20poly1305_encrypt(const uint8_t key[DW_AEAD_KEY],
                                 const uint8_t nonce[DW_AEAD_NONCE],
                                 const uint8_t *aad, size_t aadlen,
                                 const uint8_t *pt, size_t ptlen,
                                 uint8_t *ct, uint8_t tag[DW_AEAD_TAG]);

/* Verify (tag) and decrypt (ct) into (pt). Returns 1 and writes (pt) only if the
   tag is valid; on failure returns 0 and zeroes (pt), so a forged or corrupted
   message never yields plaintext. Constant-time tag comparison. */
int dw_chacha20poly1305_decrypt(const uint8_t key[DW_AEAD_KEY],
                                const uint8_t nonce[DW_AEAD_NONCE],
                                const uint8_t *aad, size_t aadlen,
                                const uint8_t *ct, size_t ctlen,
                                const uint8_t tag[DW_AEAD_TAG],
                                uint8_t *pt);

#endif /* DOGEWALLET_AEAD_H */
