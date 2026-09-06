/* koinu.dog - base58 and base58check
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * The classic O(n^2) big-integer conversion. Inputs here are keys and
 * addresses, tens of bytes, so the simple form is the right one. Bounded by
 * fixed buffers rather than allocating, and it refuses anything larger. */

#include "base58.h"
#include "sha2.h"
#include "mem.h"

#include <string.h>

static const char *B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

#define KW_B58_MAX_BYTES 256
#define KW_B58_MAX_DIGITS 512   /* > KW_B58_MAX_BYTES * log(256)/log(58) */

size_t kw_base58_encode(const uint8_t *in, size_t inlen, char *out, size_t outcap)
{
    if (inlen > KW_B58_MAX_BYTES) return 0;

    size_t zeros = 0;
    while (zeros < inlen && in[zeros] == 0) zeros++;

    uint8_t digits[KW_B58_MAX_DIGITS];
    size_t size = (inlen - zeros) * 138 / 100 + 1;
    if (size > sizeof digits) return 0;
    memset(digits, 0, size);

    for (size_t i = zeros; i < inlen; i++) {
        int carry = in[i];
        for (size_t j = size; j-- > 0; ) {
            carry += 256 * digits[j];
            digits[j] = (uint8_t)(carry % 58);
            carry /= 58;
        }
    }

    size_t it = 0;
    while (it < size && digits[it] == 0) it++;

    size_t n = zeros + (size - it);
    if (n + 1 > outcap) return 0;

    size_t k = 0;
    for (size_t i = 0; i < zeros; i++) out[k++] = '1';
    for (; it < size; it++) out[k++] = B58[digits[it]];
    out[k] = '\0';
    return k;
}

int kw_base58_decode(const char *in, uint8_t *out, size_t outcap, size_t *outlen)
{
    size_t inlen = strlen(in);
    if (inlen > KW_B58_MAX_DIGITS) return 0;

    size_t zeros = 0;
    while (in[zeros] == '1') zeros++;

    uint8_t bytes[KW_B58_MAX_DIGITS];
    size_t size = inlen * 733 / 1000 + 1;   /* log(58)/log(256) ~ 0.733 */
    if (size > sizeof bytes) return 0;
    memset(bytes, 0, size);

    for (size_t i = zeros; i < inlen; i++) {
        const char *p = strchr(B58, in[i]);
        if (!p || in[i] == '\0') return 0;
        int carry = (int)(p - B58);
        for (size_t j = size; j-- > 0; ) {
            carry += 58 * bytes[j];
            bytes[j] = (uint8_t)(carry % 256);
            carry /= 256;
        }
        if (carry) return 0;
    }

    size_t it = 0;
    while (it < size && bytes[it] == 0) it++;

    size_t n = zeros + (size - it);
    if (n > outcap) return 0;

    size_t k = 0;
    for (size_t i = 0; i < zeros; i++) out[k++] = 0;
    for (; it < size; it++) out[k++] = bytes[it];
    *outlen = k;
    return 1;
}

size_t kw_base58check_encode(const uint8_t *payload, size_t len, char *out, size_t outcap)
{
    if (len > KW_B58_MAX_BYTES - 4) return 0;
    uint8_t buf[KW_B58_MAX_BYTES];
    memcpy(buf, payload, len);
    uint8_t chk[KW_SHA256_LEN];
    kw_hash256(payload, len, chk);
    memcpy(buf + len, chk, 4);
    size_t n = kw_base58_encode(buf, len + 4, out, outcap);
    kw_secure_zero(buf, sizeof buf);
    return n;
}

int kw_base58check_decode(const char *in, uint8_t *out, size_t outcap, size_t *outlen)
{
    uint8_t buf[KW_B58_MAX_BYTES];
    size_t n = 0;
    if (!kw_base58_decode(in, buf, sizeof buf, &n)) return 0;
    if (n < 4) return 0;
    size_t plen = n - 4;
    uint8_t chk[KW_SHA256_LEN];
    kw_hash256(buf, plen, chk);
    if (kw_memeq_ct(chk, buf + plen, 4) != 0) { kw_secure_zero(buf, sizeof buf); return 0; }
    if (plen > outcap) { kw_secure_zero(buf, sizeof buf); return 0; }
    memcpy(out, buf, plen);
    *outlen = plen;
    kw_secure_zero(buf, sizeof buf);
    return 1;
}
