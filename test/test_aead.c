/* dogewallet - ChaCha20-Poly1305 tests (RFC 8439 vectors)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "chacha20.h"
#include "aead.h"
#include "testutil.h"
#include "poly1305-donna.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    /* ChaCha20 keystream block, RFC 8439 section 2.3.2 */
    {
        uint8_t key[32], nonce[12], blk[64];
        dw_test_unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", key);
        dw_test_unhex("000000090000004a00000000", nonce);
        dw_chacha20_block(key, 1, nonce, blk);
        dw_test_check("chacha20 block", blk, 64,
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
            "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e");
    }

    /* Poly1305, RFC 8439 section 2.5.2 */
    {
        uint8_t key[32]; uint8_t mac[16];
        dw_test_unhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b", key);
        const char *m = "Cryptographic Forum Research Group";
        poly1305_context ctx;
        poly1305_init(&ctx, key);
        poly1305_update(&ctx, (const uint8_t *)m, strlen(m));
        poly1305_finish(&ctx, mac);
        dw_test_check("poly1305", mac, 16, "a8061dc1305136c6c22b8baf0c0127a9");
    }

    /* ChaCha20-Poly1305 AEAD, RFC 8439 section 2.8.2 */
    {
        uint8_t key[32], nonce[12], aad[12];
        dw_test_unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", key);
        dw_test_unhex("070000004041424344454647", nonce);
        int aadlen = dw_test_unhex("50515253c0c1c2c3c4c5c6c7", aad);
        const char *pt = "Ladies and Gentlemen of the class of '99: If I could offer you only "
                         "one tip for the future, sunscreen would be it.";
        size_t ptlen = strlen(pt);

        uint8_t ct[256], tag[16];
        dw_chacha20poly1305_encrypt(key, nonce, aad, aadlen, (const uint8_t *)pt, ptlen, ct, tag);
        dw_test_check("aead ciphertext", ct, ptlen,
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63"
            "dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b369"
            "2ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3"
            "ff4def08e4b7a9de576d26586cec64b6116");
        dw_test_check("aead tag", tag, 16, "1ae10b594f09e26a7e902ecbd0600691");

        /* decrypt round trip */
        uint8_t back[256];
        if (!dw_chacha20poly1305_decrypt(key, nonce, aad, aadlen, ct, ptlen, tag, back)) {
            fprintf(stderr, "FAIL: decrypt rejected a valid tag\n"); return 1;
        }
        if (memcmp(back, pt, ptlen) != 0) { fprintf(stderr, "FAIL: decrypt plaintext\n"); return 1; }

        /* a flipped tag must be rejected, and no plaintext returned */
        uint8_t bad[16]; memcpy(bad, tag, 16); bad[0] ^= 1;
        uint8_t leak[256]; memset(leak, 0x5a, sizeof leak);
        if (dw_chacha20poly1305_decrypt(key, nonce, aad, aadlen, ct, ptlen, bad, leak)) {
            fprintf(stderr, "FAIL: decrypt accepted a forged tag\n"); return 1;
        }
        for (size_t i = 0; i < ptlen; i++) if (leak[i] != 0) { fprintf(stderr, "FAIL: plaintext leaked on bad tag\n"); return 1; }
    }

    if (dw_test_fails()) { fprintf(stderr, "%d aead vector(s) failed\n", dw_test_fails()); return 1; }
    printf("aead ok: rfc 8439 chacha20 block, poly1305, and chacha20-poly1305 with forgery rejection\n");
    return 0;
}
