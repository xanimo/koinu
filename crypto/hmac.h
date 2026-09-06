/* koinu.dog - HMAC over SHA-256 and SHA-512 (RFC 2104)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#ifndef KOINU_HMAC_H
#define KOINU_HMAC_H

#include <stddef.h>
#include <stdint.h>

#include "sha2.h"

/* out is KW_SHA256_LEN / KW_SHA512_LEN bytes. */
void kw_hmac_sha256(const uint8_t *key, size_t keylen,
                    const uint8_t *msg, size_t msglen,
                    uint8_t out[KW_SHA256_LEN]);

void kw_hmac_sha512(const uint8_t *key, size_t keylen,
                    const uint8_t *msg, size_t msglen,
                    uint8_t out[KW_SHA512_LEN]);

#endif /* KOINU_HMAC_H */
