/* dogewallet - hex encode/decode
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "hex.h"

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

size_t dw_hex_encode(const uint8_t *in, size_t inlen, char *out, size_t outcap)
{
    static const char *d = "0123456789abcdef";
    if (outcap < inlen * 2 + 1) return 0;
    for (size_t i = 0; i < inlen; i++) {
        out[2*i]     = d[in[i] >> 4];
        out[2*i + 1] = d[in[i] & 0x0f];
    }
    out[inlen * 2] = '\0';
    return inlen * 2;
}

int dw_hex_decode(const char *hex, size_t hexlen, uint8_t *out, size_t outlen)
{
    if (hexlen != outlen * 2) return 0;
    for (size_t i = 0; i < outlen; i++) {
        int hi = hexval(hex[2*i]), lo = hexval(hex[2*i + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
}
