/* koinu.dog - keystore tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "keystore.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    /* light argon2 params so the test is quick; the format is what matters here */
    kw_keystore_params pr = { 1, 16384, 1 };
    uint8_t secret[64];
    for (int i = 0; i < 64; i++) secret[i] = (uint8_t)(i * 7 + 1);
    const char *pass = "correct horse battery staple";

    uint8_t blob[4096];
    size_t n = kw_keystore_seal(secret, sizeof secret, pass, &pr, blob, sizeof blob);
    if (!n) { fprintf(stderr, "FAIL: seal\n"); return 1; }
    if (n != kw_keystore_sealed_size(sizeof secret)) { fprintf(stderr, "FAIL: sealed size\n"); return 1; }

    /* right passphrase recovers the secret */
    uint8_t back[64]; size_t bl = 0;
    if (!kw_keystore_open(blob, n, pass, back, sizeof back, &bl)) { fprintf(stderr, "FAIL: open\n"); return 1; }
    if (bl != sizeof secret || memcmp(back, secret, sizeof secret) != 0) { fprintf(stderr, "FAIL: secret mismatch\n"); return 1; }

    /* wrong passphrase yields nothing */
    if (kw_keystore_open(blob, n, "wrong passphrase", back, sizeof back, &bl)) {
        fprintf(stderr, "FAIL: wrong passphrase opened\n"); return 1;
    }

    /* tampering anywhere fails the tag: header param, salt, ciphertext, tag */
    size_t spots[] = { 8 /*t_cost*/, 20 /*salt*/, 36 /*nonce*/, 52 /*ciphertext*/, n - 1 /*tag*/ };
    for (size_t i = 0; i < sizeof spots / sizeof spots[0]; i++) {
        uint8_t t[4096]; memcpy(t, blob, n);
        t[spots[i]] ^= 1;
        if (kw_keystore_open(t, n, pass, back, sizeof back, &bl)) {
            fprintf(stderr, "FAIL: tampered byte at %zu opened\n", spots[i]); return 1;
        }
    }

    /* a truncated blob is refused */
    if (kw_keystore_open(blob, n - 1, pass, back, sizeof back, &bl)) {
        fprintf(stderr, "FAIL: truncated blob opened\n"); return 1;
    }

    /* fresh salt+nonce each time, so two seals of the same input differ */
    uint8_t blob2[4096];
    size_t n2 = kw_keystore_seal(secret, sizeof secret, pass, &pr, blob2, sizeof blob2);
    if (n2 != n || memcmp(blob, blob2, n) == 0) { fprintf(stderr, "FAIL: seals not randomized\n"); return 1; }
    if (!kw_keystore_open(blob2, n2, pass, back, sizeof back, &bl) || memcmp(back, secret, 64)) {
        fprintf(stderr, "FAIL: second seal does not open\n"); return 1;
    }

    printf("keystore ok: round trip, wrong passphrase, tamper rejection, randomized seals\n");
    return 0;
}
