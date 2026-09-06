/* koinu.dog - address and WIF encoding
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "address.h"
#include "ripemd160.h"
#include "base58.h"
#include "mem.h"

#include <string.h>

size_t kw_address_p2pkh(const uint8_t pub[33], uint8_t version, char *out, size_t outcap)
{
    uint8_t buf[21];
    buf[0] = version;
    kw_hash160(pub, 33, buf + 1);
    return kw_base58check_encode(buf, sizeof buf, out, outcap);
}

size_t kw_address_p2sh(const uint8_t *script, size_t scriptlen, uint8_t version,
                       char *out, size_t outcap)
{
    uint8_t buf[21];
    buf[0] = version;
    kw_hash160(script, scriptlen, buf + 1);
    return kw_base58check_encode(buf, sizeof buf, out, outcap);
}

size_t kw_wif_encode(const uint8_t sk[32], int compressed, uint8_t version,
                     char *out, size_t outcap)
{
    uint8_t buf[34];
    buf[0] = version;
    memcpy(buf + 1, sk, 32);
    size_t len = 33;
    if (compressed) { buf[33] = 0x01; len = 34; }
    size_t n = kw_base58check_encode(buf, len, out, outcap);
    kw_secure_zero(buf, sizeof buf);
    return n;
}

int kw_wif_decode(const char *wif, uint8_t sk[32], int *compressed, uint8_t *version)
{
    uint8_t buf[40];
    size_t n = 0;
    if (!kw_base58check_decode(wif, buf, sizeof buf, &n)) return 0;

    int ok = 1, comp = 0;
    if (n == 34 && buf[33] == 0x01) comp = 1;
    else if (n == 33)               comp = 0;
    else                            ok = 0;

    if (ok) {
        if (version) *version = buf[0];
        memcpy(sk, buf + 1, 32);
        if (compressed) *compressed = comp;
    }
    kw_secure_zero(buf, sizeof buf);
    return ok;
}
