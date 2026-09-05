/* dogewallet - address and WIF encoding
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#ifndef DOGEWALLET_ADDRESS_H
#define DOGEWALLET_ADDRESS_H

#include <stddef.h>
#include <stdint.h>

/* base58check(version || hash160(pubkey)). (pub) is compressed, 33 bytes.
   Returns the string length or 0. */
size_t dw_address_p2pkh(const uint8_t pub[33], uint8_t version, char *out, size_t outcap);

/* base58check(version || hash160(script)). */
size_t dw_address_p2sh(const uint8_t *script, size_t scriptlen, uint8_t version,
                       char *out, size_t outcap);

/* WIF: base58check(version || sk[32] [|| 0x01 if compressed]). */
size_t dw_wif_encode(const uint8_t sk[32], int compressed, uint8_t version,
                     char *out, size_t outcap);

/* Decode a WIF, returning the 32-byte secret, whether it marks a compressed
   key, and its version byte. Returns 1 on success, 0 on a bad checksum or an
   unexpected length. */
int dw_wif_decode(const char *wif, uint8_t sk[32], int *compressed, uint8_t *version);

#endif /* DOGEWALLET_ADDRESS_H */
