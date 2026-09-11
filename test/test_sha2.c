/* koinu.dog - SHA-2 known-answer tests (FIPS 180-4 vectors)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "sha2.h"
#include "cpu.h"
#include "testutil.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    uint8_t o[64];

    /* SHA-256 */
    kw_sha256("", 0, o);
    kw_test_check("sha256(\"\")", o, 32,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    kw_sha256("abc", 3, o);
    kw_test_check("sha256(\"abc\")", o, 32,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    /* SHA-512 */
    kw_sha512("", 0, o);
    kw_test_check("sha512(\"\")", o, 64,
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce4"
        "7d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    kw_sha512("abc", 3, o);
    kw_test_check("sha512(\"abc\")", o, 64,
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");

    /* one million 'a', which spans many blocks and exercises the length counter */
    {
        kw_sha256_ctx c; kw_sha256_init(&c);
        kw_sha512_ctx d; kw_sha512_init(&d);
        char chunk[1000];
        memset(chunk, 'a', sizeof chunk);
        for (int i = 0; i < 1000; i++) {
            kw_sha256_update(&c, chunk, sizeof chunk);
            kw_sha512_update(&d, chunk, sizeof chunk);
        }
        kw_sha256_final(&c, o);
        kw_test_check("sha256(1e6 x 'a')", o, 32,
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
        kw_sha512_final(&d, o);
        kw_test_check("sha512(1e6 x 'a')", o, 64,
            "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
            "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b");
    }

    /* streaming must equal one-shot: feed "abc" a byte at a time */
    {
        kw_sha256_ctx c; kw_sha256_init(&c);
        kw_sha256_update(&c, "a", 1);
        kw_sha256_update(&c, "b", 1);
        kw_sha256_update(&c, "c", 1);
        kw_sha256_final(&c, o);
        kw_test_check("sha256 streamed \"abc\"", o, 32,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    /* hash256 = double SHA-256, Bitcoin's convention */
    kw_hash256("", 0, o);
    kw_test_check("hash256(\"\")", o, 32,
        "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456");

    if (kw_test_fails()) { fprintf(stderr, "%d sha2 vector(s) failed\n", kw_test_fails()); return 1; }
    /* The hardware core, where there is one. A core that disagrees with the scalar
       one is switched off at first use, which would leave this passing while quietly
       hashing the slow way, so the point of this check is the other direction: if the
       CPU advertises the instructions, the backend must actually be using them. A
       core I got wrong fails here rather than shipping as "works, just slower". */
    {
        uint32_t want_hw = 0;
#if defined(__x86_64__) || defined(__i386__)
        want_hw = kw_cpu_has(KW_CPU_SHANI | KW_CPU_SSE41 | KW_CPU_SSSE3);
#elif defined(__aarch64__)
        want_hw = kw_cpu_has(KW_CPU_SHA2);
#endif
        if (want_hw && !kw_sha256_hw()) {
            fprintf(stderr, "FAIL: this cpu has the sha-256 instructions but the core "
                            "disagreed with the scalar one and was refused\n");
            return 1;
        }
        if (!want_hw && kw_sha256_hw()) {
            fprintf(stderr, "FAIL: the hardware core is on without the instructions\n");
            return 1;
        }

        /* and where it is in use, hold it against the scalar core over random blocks,
           which is what caught a transposed register in the scrypt core */
        if (kw_sha256_hw()) {
            unsigned seed = 3;
            for (int i = 0; i < 256; i++) {
                uint8_t blk[64];
                uint32_t a[8], b[8];
                for (int k = 0; k < 64; k++) { seed = seed * 1103515245u + 12345u; blk[k] = (uint8_t)(seed >> 16); }
                for (int k = 0; k < 8; k++) { seed = seed * 1103515245u + 12345u; a[k] = b[k] = seed; }
                kw_sha256_compress_hw(a, blk);
                kw_sha256_compress_scalar(b, blk);
                if (memcmp(a, b, sizeof a) != 0) {
                    fprintf(stderr, "FAIL: the %s core disagrees with the scalar one at block %d\n",
                            kw_sha256_backend(), i);
                    return 1;
                }
            }
        }
    }

    printf("sha2 ok: sha256, sha512, 1e6-byte, streamed, hash256 vectors match,\n"
       "  %s core%s\n", kw_sha256_backend(),
       kw_sha256_hw() ? " == scalar over 256 random blocks" : " (no sha-256 instructions here)");
    return 0;
}
