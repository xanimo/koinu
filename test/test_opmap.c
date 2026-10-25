/* koinu.dog - the outpoint to script map
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * The map is what lets koinu produce basic filters rather than only consume
 * them, so a wrong answer here is a filter that hides a payment. Two things are
 * most likely to be wrong and both are attacked directly: deletion, because a
 * spend removes an entry and linear probing breaks if the gap is left behind,
 * and the long-script path, because it owns memory the inline one does not. */

#include "opmap.h"

#include <stdio.h>
#include <string.h>

static void mkop(uint8_t op[36], uint32_t i, uint32_t vout)
{
    memset(op, 0, 36);
    op[0] = (uint8_t)(i & 0xff);
    op[1] = (uint8_t)((i >> 8) & 0xff);
    op[2] = (uint8_t)((i >> 16) & 0xff);
    op[3] = (uint8_t)((i >> 24) & 0xff);
    op[32] = (uint8_t)(vout & 0xff);
    op[33] = (uint8_t)((vout >> 8) & 0xff);
}

static void mkspk(uint8_t spk[25], uint32_t i)
{
    spk[0] = 0x76; spk[1] = 0xa9; spk[2] = 0x14;
    for (int k = 0; k < 20; k++) spk[3 + k] = (uint8_t)(i + k);
    spk[23] = 0x88; spk[24] = 0xac;
}

int main(void)
{
    kw_opmap *m = kw_opmap_new();
    if (!m) { fprintf(stderr, "FAIL: no map\n"); return 1; }

    /* an absent outpoint is absent */
    {
        uint8_t op[36], got[64]; size_t gl = 0;
        mkop(op, 7, 0);
        if (kw_opmap_take(m, op, got, sizeof got, &gl)) {
            fprintf(stderr, "FAIL: took an outpoint never put\n"); return 1;
        }
    }

    /* Enough entries to force several growths, each read back exactly. The vout
       varies too, so two outputs of one transaction are distinct keys: folding
       them would put one script in place of the other. */
    const uint32_t N = 20000;
    for (uint32_t i = 0; i < N; i++) {
        uint8_t op[36], spk[25];
        mkop(op, i, i % 3);
        mkspk(spk, i);
        if (!kw_opmap_put(m, op, spk, sizeof spk)) {
            fprintf(stderr, "FAIL: put %u\n", i); return 1;
        }
    }
    if (kw_opmap_count(m) != N) {
        fprintf(stderr, "FAIL: count %zu, expected %u\n", kw_opmap_count(m), N); return 1;
    }

    /* Take every other one, which leaves the table half full of holes: this is
       where a probe chain broken by deletion shows up, because the entries left
       behind are reached through the gaps. */
    for (uint32_t i = 0; i < N; i += 2) {
        uint8_t op[36], want[25], got[64]; size_t gl = 0;
        mkop(op, i, i % 3);
        mkspk(want, i);
        if (!kw_opmap_take(m, op, got, sizeof got, &gl)) {
            fprintf(stderr, "FAIL: take %u went missing\n", i); return 1;
        }
        if (gl != sizeof want || memcmp(got, want, gl) != 0) {
            fprintf(stderr, "FAIL: take %u gave the wrong script\n", i); return 1;
        }
    }
    if (kw_opmap_count(m) != N / 2) {
        fprintf(stderr, "FAIL: count after deletes %zu\n", kw_opmap_count(m)); return 1;
    }

    /* everything not taken is still reachable and still right */
    for (uint32_t i = 1; i < N; i += 2) {
        uint8_t op[36], want[25], got[64]; size_t gl = 0;
        mkop(op, i, i % 3);
        mkspk(want, i);
        if (!kw_opmap_take(m, op, got, sizeof got, &gl)) {
            fprintf(stderr, "FAIL: %u lost after the gaps opened\n", i); return 1;
        }
        if (gl != sizeof want || memcmp(got, want, gl) != 0) {
            fprintf(stderr, "FAIL: %u wrong after the gaps opened\n", i); return 1;
        }
    }
    if (kw_opmap_count(m) != 0) {
        fprintf(stderr, "FAIL: map not empty, %zu left\n", kw_opmap_count(m)); return 1;
    }

    /* a second take of the same outpoint finds nothing: an outpoint spends once */
    {
        uint8_t op[36], spk[25], got[64]; size_t gl = 0;
        mkop(op, 1234, 0);
        mkspk(spk, 1234);
        kw_opmap_put(m, op, spk, sizeof spk);
        if (!kw_opmap_take(m, op, got, sizeof got, &gl)) {
            fprintf(stderr, "FAIL: first take\n"); return 1;
        }
        if (kw_opmap_take(m, op, got, sizeof got, &gl)) {
            fprintf(stderr, "FAIL: an outpoint was spent twice\n"); return 1;
        }
    }

    /* Scripts past the inline bound live elsewhere and must come back whole.
       Put and take them repeatedly so the released slots are reused, which is
       where a double free or a stale pointer would show. */
    for (int round = 0; round < 3; round++) {
        for (uint32_t i = 0; i < 200; i++) {
            uint8_t op[36], big[400], got[512]; size_t gl = 0;
            size_t bl = 26 + (i % 300);
            mkop(op, 900000 + i, 0);
            for (size_t k = 0; k < bl; k++) big[k] = (uint8_t)(i + k + round);
            if (!kw_opmap_put(m, op, big, bl)) {
                fprintf(stderr, "FAIL: put long %u\n", i); return 1;
            }
            if (!kw_opmap_take(m, op, got, sizeof got, &gl) || gl != bl ||
                memcmp(got, big, bl) != 0) {
                fprintf(stderr, "FAIL: long script %u did not round trip\n", i); return 1;
            }
        }
    }

    /* an empty script is a legal scriptPubKey and has to round trip as one */
    {
        uint8_t op[36], got[8]; size_t gl = 99;
        mkop(op, 55555, 0);
        if (!kw_opmap_put(m, op, NULL, 0)) { fprintf(stderr, "FAIL: put empty\n"); return 1; }
        if (!kw_opmap_take(m, op, got, sizeof got, &gl) || gl != 0) {
            fprintf(stderr, "FAIL: the empty script did not round trip (%zu)\n", gl); return 1;
        }
    }

    /* replacing a key keeps one entry, not two, and gives back the new script */
    {
        uint8_t op[36], a[25], b[400], got[512]; size_t gl = 0;
        mkop(op, 4242, 1);
        mkspk(a, 1);
        memset(b, 0xab, sizeof b);
        size_t before = kw_opmap_count(m);
        if (!kw_opmap_put(m, op, a, sizeof a) ||
            !kw_opmap_put(m, op, b, 300)) {
            fprintf(stderr, "FAIL: replace\n"); return 1;
        }
        if (kw_opmap_count(m) != before + 1) {
            fprintf(stderr, "FAIL: a replaced key counted twice\n"); return 1;
        }
        if (!kw_opmap_take(m, op, got, sizeof got, &gl) || gl != 300 ||
            memcmp(got, b, 300) != 0) {
            fprintf(stderr, "FAIL: replace gave the old script\n"); return 1;
        }
    }

    printf("opmap ok: %u entries through several growths, read back exactly with\n"
           "  half the table deleted and the rest still reachable, an outpoint spent\n"
           "  once, long scripts round tripping across reused slots, an empty script,\n"
           "  and a replaced key counted once\n", N);
    kw_opmap_free(m);
    return 0;
}
