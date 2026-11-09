/* koinu.dog - keystore tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "keystore.h"
#include "seedfile.h"

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

    /* What the keystore actually seals for a wallet. The birthday rides inside
       the sealed bytes rather than in the keystore header, so it is covered by
       the tag and a keystore written before it existed is still exactly 64
       bytes of seed. */
    {
        uint8_t seed[KW_SEED_LEN], back[KW_SEED_LEN];
        for (size_t i = 0; i < sizeof seed; i++) seed[i] = (uint8_t)(i * 7 + 1);

        kw_birthday b = { 6447218, { 0 } };
        for (int i = 0; i < 32; i++) b.hash[i] = (uint8_t)(0xa0 + i);

        uint8_t packed[KW_SEEDFILE_MAX];
        size_t n = kw_seedfile_pack(seed, &b, packed, sizeof packed);
        if (n != KW_SEED_LEN + 40) {
            fprintf(stderr, "FAIL: packed length %zu, want %d\n", n, KW_SEED_LEN + 40); return 1; }

        kw_birthday got = { 0, { 0 } };
        if (!kw_seedfile_unpack(packed, n, back, &got) ||
            memcmp(back, seed, sizeof seed) != 0 ||
            got.height != b.height || memcmp(got.hash, b.hash, 32) != 0) {
            fprintf(stderr, "FAIL: birthday did not survive a round trip\n"); return 1; }

        /* No birthday writes no trailer, so such a keystore is byte-identical
           to one from before any of this. */
        size_t n0 = kw_seedfile_pack(seed, NULL, packed, sizeof packed);
        if (n0 != KW_SEED_LEN) {
            fprintf(stderr, "FAIL: a wallet with no birthday packed %zu bytes\n", n0); return 1; }
        got.height = 1;
        if (!kw_seedfile_unpack(packed, n0, back, &got) || got.height != 0) {
            fprintf(stderr, "FAIL: a seed with no trailer did not read back as no birthday\n");
            return 1; }

        /* A height of zero is the same as none, and pack must not write a
           trailer claiming it, since unpack reads that as a built-by-hand blob. */
        kw_birthday zero = { 0, { 0 } };
        if (kw_seedfile_pack(seed, &zero, packed, sizeof packed) != KW_SEED_LEN) {
            fprintf(stderr, "FAIL: height 0 wrote a trailer\n"); return 1; }

        /* Everything that is not one of those two shapes is refused rather than
           read as a seed with something after it. */
        n = kw_seedfile_pack(seed, &b, packed, sizeof packed);
        packed[KW_SEED_LEN] ^= 0xff;                      /* broken tag */
        if (kw_seedfile_unpack(packed, n, back, &got)) {
            fprintf(stderr, "FAIL: a bad trailer tag was accepted\n"); return 1; }
        packed[KW_SEED_LEN] ^= 0xff;
        if (kw_seedfile_unpack(packed, n - 1, back, &got) ||
            kw_seedfile_unpack(packed, KW_SEED_LEN + 1, back, &got)) {
            fprintf(stderr, "FAIL: a short trailer was accepted\n"); return 1; }
        memset(packed + KW_SEED_LEN + 4, 0, 4);           /* trailer saying height 0 */
        if (kw_seedfile_unpack(packed, n, back, &got)) {
            fprintf(stderr, "FAIL: a trailer claiming height 0 was accepted\n"); return 1; }

        /* And it survives the seal, which is the only path that matters. */
        n = kw_seedfile_pack(seed, &b, packed, sizeof packed);
        uint8_t blob[512];
        size_t bn = kw_keystore_seal(packed, n, "pw", &KW_KEYSTORE_DEFAULT, blob, sizeof blob);
        uint8_t out[KW_SEEDFILE_MAX]; size_t olen = 0;
        if (!bn || !kw_keystore_open(blob, bn, "pw", out, sizeof out, &olen) ||
            !kw_seedfile_unpack(out, olen, back, &got) ||
            got.height != b.height || memcmp(back, seed, sizeof seed) != 0) {
            fprintf(stderr, "FAIL: the birthday did not survive a seal and open\n"); return 1; }
    }

    printf("keystore ok: round trip, wrong passphrase, tamper rejection, randomized seals,\n"
           "  kdf parameters bounded, and a birthday sealed beside the seed with\n"
           "  pre-birthday keystores still opening\n");
    return 0;
}
