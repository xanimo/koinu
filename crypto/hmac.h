/* dogewallet - HMAC over SHA-256 and SHA-512 (RFC 2104)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#ifndef DOGEWALLET_HMAC_H
#define DOGEWALLET_HMAC_H

#include <stddef.h>
#include <stdint.h>

#include "sha2.h"

/* out is DW_SHA256_LEN / DW_SHA512_LEN bytes. */
void dw_hmac_sha256(const uint8_t *key, size_t keylen,
                    const uint8_t *msg, size_t msglen,
                    uint8_t out[DW_SHA256_LEN]);

void dw_hmac_sha512(const uint8_t *key, size_t keylen,
                    const uint8_t *msg, size_t msglen,
                    uint8_t out[DW_SHA512_LEN]);

#endif /* DOGEWALLET_HMAC_H */
