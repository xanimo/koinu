/* koinu.dog - RIPEMD-160 known-answer tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Vectors from the RIPEMD-160 specification (Dobbertin, Bosselaers, Preneel).
 * The hash160 case pairs it with SHA-256 on the compressed-pubkey example from
 * the Bitcoin address documentation. */

#include "ripemd160.h"
#include "sha2.h"
#include "testutil.h"

#include <stdio.h>
#include <string.h>

static void rmd(const char *s, const char *want, const char *name)
{
    uint8_t o[20];
    kw_ripemd160(s, strlen(s), o);
    kw_test_check(name, o, 20, want);
}

int main(void)
{
    uint8_t o[20];

    rmd("", "9c1185a5c5e9fc54612808977ee8f548b2258d31", "rmd(\"\")");
    rmd("a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe", "rmd(\"a\")");
    rmd("abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc", "rmd(\"abc\")");
    rmd("message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36", "rmd(\"message digest\")");
    rmd("abcdefghijklmnopqrstuvwxyz",
        "f71c27109c692c1b56bbdceb5b9d2865b3708dbc", "rmd(a..z)");
    rmd("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "12a053384a9c0c88e405a06c27dcf49ada62eb2b", "rmd(56-char)");
    rmd("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "b0e20b6e3116640286ed3a87a5713079b21f5189", "rmd(A-Za-z0-9)");
    rmd("12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        "9b752e45573d4b39f4dbd3323cab82bf63326bfb", "rmd(8x'1234567890')");

    /* one million 'a', spanning many blocks */
    {
        kw_ripemd160_ctx c; kw_ripemd160_init(&c);
        char chunk[1000];
        memset(chunk, 'a', sizeof chunk);
        for (int i = 0; i < 1000; i++) kw_ripemd160_update(&c, chunk, sizeof chunk);
        kw_ripemd160_final(&c, o);
        kw_test_check("rmd(1e6 x 'a')", o, 20,
            "52783243c1697bdbe16d37f97f68f08325dc1528");
    }

    /* hash160 = ripemd160(sha256(x)). check wiring against the two primitives,
       then against the Bitcoin compressed-pubkey example. */
    {
        static const uint8_t pub[33] = {
            0x02,0x50,0x86,0x3a,0xd6,0x4a,0x87,0xae,0x8a,0x2f,0xe8,0x3c,0x1a,0xf1,
            0xa8,0x40,0x3c,0xb5,0x3f,0x53,0xe4,0x86,0xd8,0x51,0x1d,0xad,0x8a,0x04,
            0x88,0x7e,0x5b,0x23,0x52
        };
        uint8_t sha[32], man[20], got[20];
        kw_sha256(pub, sizeof pub, sha);
        kw_ripemd160(sha, sizeof sha, man);
        kw_hash160(pub, sizeof pub, got);
        if (memcmp(man, got, 20) != 0) {
            fprintf(stderr, "FAIL hash160 wiring differs from sha256+ripemd160\n");
            return 1;
        }
        kw_test_check("hash160(compressed pubkey)", got, 20,
            "f54a5851e9372b87810a8e60cdd2e7cfd80b6e31");
    }

    if (kw_test_fails()) { fprintf(stderr, "%d ripemd160 vector(s) failed\n", kw_test_fails()); return 1; }
    printf("ripemd160 ok: spec vectors, 1e6-byte, and hash160 match\n");
    return 0;
}
