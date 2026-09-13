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


    /* The KDF parameters come out of the file header and drive argon2 before the tag
       can be checked, so a tampered t_cost is a hang rather than a rejection. The
       bounds are what stops that, and they are checked here rather than by noticing a
       test got slow: one past either knob must be refused. */
    {
        uint8_t t[sizeof blob];
        memcpy(t, blob, n);
        static const struct { size_t at; uint32_t v; const char *what; } over[] = {
            { 8,  KW_KEYSTORE_MAX_T_COST + 1,      "t_cost" },
            { 8,  0xffffffffu,                     "t_cost at the top of the type" },
            { 12, KW_KEYSTORE_MAX_M_COST_KIB + 1,  "m_cost" },
            { 16, KW_KEYSTORE_MAX_PARALLELISM + 1, "parallelism" }
        };
        for (size_t i = 0; i < sizeof over / sizeof *over; i++) {
            uint8_t out2[64];
            size_t got = 0;
            memcpy(t, blob, n);
            t[over[i].at + 0] = (uint8_t)over[i].v;
            t[over[i].at + 1] = (uint8_t)(over[i].v >> 8);
            t[over[i].at + 2] = (uint8_t)(over[i].v >> 16);
            t[over[i].at + 3] = (uint8_t)(over[i].v >> 24);
            if (kw_keystore_open(t, n, pass, out2, sizeof out2, &got)) {
                fprintf(stderr, "FAIL: an out-of-range %s was accepted\n", over[i].what);
                return 1;
            }
        }
        /* and the parameters it writes are inside them, or the defaults are unopenable */
        if (KW_KEYSTORE_DEFAULT.t_cost > KW_KEYSTORE_MAX_T_COST ||
            KW_KEYSTORE_DEFAULT.m_cost_kib > KW_KEYSTORE_MAX_M_COST_KIB ||
            KW_KEYSTORE_DEFAULT.parallelism > KW_KEYSTORE_MAX_PARALLELISM) {
            fprintf(stderr, "FAIL: the default parameters are outside the accepted range\n");
            return 1;
        }
    }

    printf("keystore ok: round trip, wrong passphrase, tamper rejection, randomized seals,\n"
           "  kdf parameters bounded\n");
    return 0;
}
