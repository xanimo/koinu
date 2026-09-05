/* dogewallet - base58 and base58check tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Raw vectors from Bitcoin Core's base58 test data; the base58check cases are
 * the classic address examples (version 0x00 || hash160). */

#include "base58.h"
#include "testutil.h"

#include <stdio.h>
#include <string.h>

static int fails = 0;

static void enc(const uint8_t *in, size_t n, const char *want, const char *name)
{
    char out[128];
    size_t r = dw_base58_encode(in, n, out, sizeof out);
    if (!r || strcmp(out, want) != 0) {
        fprintf(stderr, "FAIL %s\n  got  %s\n  want %s\n", name, r ? out : "(fail)", want);
        fails++;
    }
}

int main(void)
{
    uint8_t b[64];
    int n;

    /* raw base58 */
    n = (int)dw_test_unhex("61", b);            enc(b, n, "2g", "b58(61)");
    n = (int)dw_test_unhex("626262", b);        enc(b, n, "a3gV", "b58(626262)");
    n = (int)dw_test_unhex("636363", b);        enc(b, n, "aPEr", "b58(636363)");
    n = (int)dw_test_unhex("73696d706c792061206c6f6e6720737472696e67", b);
    enc(b, n, "2cFupjhnEsSn59qHXstmK2ffpLv2", "b58(\"simply a long string\")");

    /* raw round-trip, including a leading-zero byte -> leading '1' */
    {
        uint8_t in[5] = {0x00, 0x01, 0x02, 0x03, 0x04};
        char s[32]; uint8_t back[5]; size_t bl = 0;
        size_t r = dw_base58_encode(in, sizeof in, s, sizeof s);
        if (!r || s[0] != '1') { fprintf(stderr, "FAIL: leading zero not '1'\n"); fails++; }
        if (!dw_base58_decode(s, back, sizeof back, &bl) || bl != 5 || memcmp(in, back, 5)) {
            fprintf(stderr, "FAIL: b58 round trip\n"); fails++;
        }
    }

    /* base58check address vectors: 0x00 || hash160 */
    {
        struct { const char *hex; const char *addr; } v[] = {
            { "00010966776006953d5567439e5e39f86a0d273bee", "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM" },
            { "00f54a5851e9372b87810a8e60cdd2e7cfd80b6e31", "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs" },
        };
        for (int i = 0; i < 2; i++) {
            uint8_t pay[21]; dw_test_unhex(v[i].hex, pay);
            char out[64];
            size_t r = dw_base58check_encode(pay, sizeof pay, out, sizeof out);
            if (!r || strcmp(out, v[i].addr) != 0) {
                fprintf(stderr, "FAIL b58check enc %d\n  got  %s\n  want %s\n",
                        i, r ? out : "(fail)", v[i].addr);
                fails++;
            }
            uint8_t back[21]; size_t bl = 0;
            if (!dw_base58check_decode(v[i].addr, back, sizeof back, &bl) ||
                bl != 21 || memcmp(pay, back, 21)) {
                fprintf(stderr, "FAIL b58check dec %d\n", i);
                fails++;
            }
        }

        /* a flipped character must fail the checksum */
        uint8_t junk[21]; size_t jl = 0;
        if (dw_base58check_decode("1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAt", junk, sizeof junk, &jl)) {
            fprintf(stderr, "FAIL: bad checksum accepted\n");
            fails++;
        }
    }

    if (fails) { fprintf(stderr, "%d base58 case(s) failed\n", fails); return 1; }
    printf("base58 ok: raw vectors, round trip, base58check addresses, checksum rejection\n");
    return 0;
}
