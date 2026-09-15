/* koinu.dog - header sync driver test (offline, over a socketpair)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * The socketpair's far end is pre-loaded with a headers message (blocks 1,2)
 * and then an empty headers message, the way a node answers two getheaders
 * rounds. The driver should append both and stop. */

#include "sync.h"
#include "peer.h"
#include "headers.h"
#include "proto.h"
#include "chainparams.h"
#include "sha2.h"
#include "hex.h"
#include "testutil.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static const char *B1_HDR =
    "04006200a573e91c1772076c0d40f70e4408c83a31705f296ae6e7629d4adcb5a360213d"
    "85711eab5e7932893bc19abe378e66701a242ec323416a743996aa672de18b26"
    "36c59c6affff7f2001000000";
static const char *B2_HDR =
    "04006200d05eaedc253dc6f2eda94e1b693bf3bbb8d2923dfec32c765d7efc667ee95a21"
    "84daf2f79c0d16ae28cc536e79f2bad55534cca9049fe8359b99c047386cdc65"
    "37c59c6affff7f2000000000";
static const char *B2_DISP = "dc413d41281d45e001b388406f4e5e31dfee12b23544972e0953bb31386cf8b7";

/* The same two headers over a fresh socketpair, against whichever parameters the
   caller wants. Returns what the driver returned. */
static long feed_two(const kw_chainparams *cp)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return -99;
    struct timeval tv = { 5, 0 };
    setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    uint8_t b1[80], b2[80];
    kw_test_unhex(B1_HDR, b1);
    kw_test_unhex(B2_HDR, b2);

    uint8_t payload[256]; size_t pn = 0;
    payload[pn++] = 0x02;
    memcpy(payload + pn, b1, 80); pn += 80; payload[pn++] = 0x00;
    memcpy(payload + pn, b2, 80); pn += 80; payload[pn++] = 0x00;
    uint8_t frame[512]; size_t fn;
    fn = kw_msg_serialize(cp->magic, "headers", payload, pn, frame, sizeof frame);
    if (write(sv[1], frame, fn) != (ssize_t)fn) { close(sv[0]); close(sv[1]); return -99; }
    uint8_t empty = 0x00;
    fn = kw_msg_serialize(cp->magic, "headers", &empty, 1, frame, sizeof frame);
    if (write(sv[1], frame, fn) != (ssize_t)fn) { close(sv[0]); close(sv[1]); return -99; }

    kw_peer p;
    kw_peer_from_fd(&p, cp->magic, sv[0]);
    kw_headerstore s;
    kw_headerstore_init(&s);
    long r = kw_sync_headers(&p, &s, cp);
    kw_headerstore_free(&s);
    kw_peer_close(&p);
    close(sv[1]);
    return r;
}

int main(void)
{
    uint32_t magic = KW_DOGE_REGTEST.magic;
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { fprintf(stderr, "FAIL: socketpair\n"); return 1; }
    struct timeval tv = { 5, 0 };
    setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    uint8_t b1[80], b2[80];
    kw_test_unhex(B1_HDR, b1);
    kw_test_unhex(B2_HDR, b2);

    /* far end: a headers message with blocks 1,2 then an empty headers message */
    uint8_t payload[256]; size_t pn = 0;
    payload[pn++] = 0x02;
    memcpy(payload + pn, b1, 80); pn += 80; payload[pn++] = 0x00;
    memcpy(payload + pn, b2, 80); pn += 80; payload[pn++] = 0x00;
    uint8_t frame[512]; size_t fn;
    fn = kw_msg_serialize(magic, "headers", payload, pn, frame, sizeof frame);
    if (write(sv[1], frame, fn) != (ssize_t)fn) { fprintf(stderr, "FAIL: preload headers\n"); return 1; }
    uint8_t empty = 0x00;
    fn = kw_msg_serialize(magic, "headers", &empty, 1, frame, sizeof frame);
    if (write(sv[1], frame, fn) != (ssize_t)fn) { fprintf(stderr, "FAIL: preload empty\n"); return 1; }

    kw_peer p;
    kw_peer_from_fd(&p, magic, sv[0]);
    kw_headerstore s;
    kw_headerstore_init(&s);

    long n = kw_sync_headers(&p, &s, &KW_DOGE_REGTEST);
    if (n != 2) { fprintf(stderr, "FAIL: appended %ld, want 2\n", n); return 1; }
    if (s.count != 2) { fprintf(stderr, "FAIL: store count %zu\n", s.count); return 1; }

    char d[65]; uint8_t r[32];
    const kw_block_header *tip = kw_headerstore_tip(&s);
    for (int i = 0; i < 32; i++) r[i] = tip->hash[31 - i];
    kw_hex_encode(r, 32, d, sizeof d);
    if (strcmp(d, B2_DISP) != 0) { fprintf(stderr, "FAIL: tip %s\n", d); return 1; }

    /* the driver should have sent two getheaders (one per round) */
    uint8_t back[1024];
    ssize_t got = read(sv[1], back, sizeof back);
    char cmd[13]; const uint8_t *pl; size_t gl;
    int c = kw_msg_parse(magic, back, got > 0 ? (size_t)got : 0, cmd, &pl, &gl);
    if (c <= 0 || strcmp(cmd, "getheaders") != 0) { fprintf(stderr, "FAIL: no getheaders sent\n"); return 1; }


    /* The retarget rule as the sync applies it, on a store rather than on values
       handed straight to net/pow.c. The numbers are mainnet's: height 240 is the
       first retarget, it reaches back to genesis for its start time, and the chain
       says its answer is 1e0fffff. Heights below it inherit, so 239 must still carry
       what genesis did.

       The store is fabricated because 239 real headers do not fit in a test, and the
       rule reads nothing from a header but its nBits and timestamp. */
    {
        kw_headerstore t;
        if (!kw_headerstore_init(&t)) { fprintf(stderr, "FAIL: store init\n"); return 1; }
        free(t.h);                              /* replacing the store's own array */
        t.h = (kw_block_header *)calloc(240, sizeof *t.h);
        if (!t.h) { fprintf(stderr, "FAIL: out of memory\n"); return 1; }
        t.cap = 240;

        for (int i = 0; i < 239; i++) {
            uint8_t *raw = t.h[i].raw;
            uint32_t when = 1386325540u + (uint32_t)(i + 1) * 30u;
            if (i == 238) when = 1386475638u;          /* height 239, from the chain */
            raw[68] = (uint8_t)when;       raw[69] = (uint8_t)(when >> 8);
            raw[70] = (uint8_t)(when >> 16); raw[71] = (uint8_t)(when >> 24);
            raw[72] = 0xf0; raw[73] = 0xff; raw[74] = 0x0f; raw[75] = 0x1e;   /* 1e0ffff0 */
        }

        t.count = 5;
        if (!kw_sync_bits_ok(&t, &KW_DOGE_MAINNET, 6, 0x1e0ffff0u))
            { fprintf(stderr, "FAIL: height 6 must inherit genesis nBits\n"); return 1; }
        if (kw_sync_bits_ok(&t, &KW_DOGE_MAINNET, 6, 0x1d00ffffu))
            { fprintf(stderr, "FAIL: height 6 accepted a difficulty it was not owed\n"); return 1; }

        t.count = 239;
        if (!kw_sync_bits_ok(&t, &KW_DOGE_MAINNET, 240, 0x1e0fffffu))
            { fprintf(stderr, "FAIL: the first retarget must demand 1e0fffff\n"); return 1; }
        if (kw_sync_bits_ok(&t, &KW_DOGE_MAINNET, 240, 0x1e0ffff0u))
            { fprintf(stderr, "FAIL: 240 accepted the difficulty it was retargeting away from\n"); return 1; }

        /* a chain whose rules are not written is not checked, rather than checked wrongly */
        if (!kw_sync_bits_ok(&t, &KW_DOGE_TESTNET, 240, 0x1d00ffffu))
            { fprintf(stderr, "FAIL: testnet must not be judged by mainnet's rule\n"); return 1; }

        kw_headerstore_free(&t);
    }

    kw_headerstore_free(&s);
    kw_peer_close(&p);
    close(sv[1]);

    /* An anchor is what says this is the chain rather than a chain. A peer can link to
       genesis, satisfy the retarget rule and carry no work at all, so the default sync
       has to check the hashes this release pins, not only the parallel fill.
       Regtest ships no anchors, so this builds a parameter set that has two. */
    {
        kw_checkpoint anchors[2] = { { 1, NULL }, { 2, B2_DISP } };
        char b1disp[65];
        uint8_t b1[80], h[32], d[32];
        kw_test_unhex(B1_HDR, b1);
        kw_hash256(b1, 80, h);
        for (int i = 0; i < 32; i++) d[i] = h[31 - i];
        kw_hex_encode(d, 32, b1disp, sizeof b1disp);
        anchors[0].hash = b1disp;

        kw_chainparams anchored = KW_DOGE_REGTEST;
        anchored.checkpoints = anchors;
        anchored.ncheckpoints = 2;

        /* the honest chain matches both and is accepted */
        if (feed_two(&anchored) != 2) { fprintf(stderr, "FAIL: anchors refused the real chain\n"); return 1; }

        /* one wrong hash at an anchor height and the whole chain goes */
        char bent[65];
        memcpy(bent, b1disp, sizeof bent);
        bent[0] = (bent[0] == 'a') ? 'b' : 'a';
        anchors[0].hash = bent;
        if (feed_two(&anchored) != -1) { fprintf(stderr, "FAIL: a chain that missed an anchor was accepted\n"); return 1; }
        anchors[0].hash = b1disp;

        /* and a chain that stops short of the newest anchor is not this chain */
        kw_checkpoint far[1] = { { 9999, B2_DISP } };
        anchored.checkpoints = far;
        anchored.ncheckpoints = 1;
        if (feed_two(&anchored) != -1) { fprintf(stderr, "FAIL: a chain ending below the last anchor was accepted\n"); return 1; }
    }


    /* The locator and the work sum, which is what choosing between chains needs. A
       synthetic chain is enough: neither reads anything but hashes and nBits. */
    {
        kw_headerstore c;
        if (!kw_headerstore_init(&c)) { fprintf(stderr, "FAIL: store init\n"); return 1; }
        uint8_t raw[80];
        memset(raw, 0, 80);
        raw[0] = 1;
        raw[72] = 0xff; raw[73] = 0xff; raw[74] = 0x00; raw[75] = 0x1d;   /* nBits */
        kw_block_header prev;
        kw_block_header_parse(raw, 80, &prev);
        if (!kw_headerstore_append(&c, &prev)) { fprintf(stderr, "FAIL: seed\n"); return 1; }
        for (int i = 2; i <= 40; i++) {
            memcpy(raw + 4, prev.hash, 32);
            raw[68] = (uint8_t)i;                    /* vary the nonce so hashes differ */
            kw_block_header h;
            kw_block_header_parse(raw, 80, &h);
            if (!kw_headerstore_append(&c, &h)) { fprintf(stderr, "FAIL: append %d\n", i); return 1; }
            prev = h;
        }

        /* ten singles then doubling: 40,39..32, then 30,26,18,2, then genesis. The
           tip comes first, every hash is one the store holds, and none repeat. */
        uint8_t loc[KW_SYNC_LOCATOR_MAX][32];
        kw_chainparams plain = KW_DOGE_REGTEST;
        plain.checkpoints = NULL; plain.ncheckpoints = 0;
        size_t nloc = kw_sync_locator(&c, &plain, loc, KW_SYNC_LOCATOR_MAX);
        if (nloc < 12 || nloc > KW_SYNC_LOCATOR_MAX)
            { fprintf(stderr, "FAIL: locator has %zu hashes\n", nloc); return 1; }
        if (memcmp(loc[0], c.h[39].hash, 32) != 0)
            { fprintf(stderr, "FAIL: locator does not start at the tip\n"); return 1; }
        for (size_t i = 0; i + 1 < nloc; i++)
            for (size_t j = i + 1; j < nloc; j++)
                if (memcmp(loc[i], loc[j], 32) == 0)
                    { fprintf(stderr, "FAIL: locator repeats hash %zu\n", i); return 1; }
        /* every entry but genesis is a header the store holds, newest first */
        for (size_t i = 0; i + 1 < nloc; i++) {
            int found = 0;
            for (size_t k = 0; k < c.count && !found; k++)
                if (memcmp(loc[i], c.h[k].hash, 32) == 0) found = 1;
            if (!found) { fprintf(stderr, "FAIL: locator hash %zu is not in the store\n", i); return 1; }
        }

        /* work adds up over a range and is zero over an empty one */
        kw_u256 w10, w20, none;
        kw_u256_zero(&w10); kw_u256_zero(&w20); kw_u256_zero(&none);
        if (!kw_sync_chainwork(&c, 0, 10, &w10) || !kw_sync_chainwork(&c, 0, 20, &w20))
            { fprintf(stderr, "FAIL: chainwork refused a range it holds\n"); return 1; }
        if (!kw_sync_chainwork(&c, 5, 5, &none) || !kw_u256_is_zero(&none))
            { fprintf(stderr, "FAIL: an empty range is not zero work\n"); return 1; }
        if (kw_u256_cmp(&w20, &w10) <= 0)
            { fprintf(stderr, "FAIL: twenty headers are not more work than ten\n"); return 1; }
        if (kw_sync_chainwork(&c, 0, 41, &w10))
            { fprintf(stderr, "FAIL: chainwork accepted a range past the tip\n"); return 1; }

        /* a harder chain beats a longer easy one, which is the whole point */
        kw_headerstore d;
        if (!kw_headerstore_init(&d)) { fprintf(stderr, "FAIL: store init\n"); return 1; }
        memset(raw, 0, 80);
        raw[0] = 1;
        raw[72] = 0xff; raw[73] = 0xff; raw[74] = 0x00; raw[75] = 0x1c;   /* 256x harder */
        kw_block_header hd;
        kw_block_header_parse(raw, 80, &hd);
        if (!kw_headerstore_append(&d, &hd)) { fprintf(stderr, "FAIL: seed hard\n"); return 1; }
        kw_u256 hard;
        kw_u256_zero(&hard);
        if (!kw_sync_chainwork(&d, 0, 1, &hard))
            { fprintf(stderr, "FAIL: chainwork on the hard chain\n"); return 1; }
        if (kw_u256_cmp(&hard, &w20) <= 0)
            { fprintf(stderr, "FAIL: one hard header does not outweigh twenty easy ones\n"); return 1; }

        /* and truncation is what adopting one costs */
        kw_headerstore_truncate(&c, 10);
        if (c.count != 10 || memcmp(kw_headerstore_tip(&c)->hash, c.h[9].hash, 32) != 0)
            { fprintf(stderr, "FAIL: truncate left %zu\n", c.count); return 1; }
        kw_headerstore_truncate(&c, 99);
        if (c.count != 10) { fprintf(stderr, "FAIL: truncate grew the store\n"); return 1; }

        kw_headerstore_free(&c);
        kw_headerstore_free(&d);
    }

    /* A cache is a chain a peer served an earlier run, and the live sync only checks
       heights it downloads itself, which a cache is by definition not. So the anchors
       are applied on load too: a store that disagrees with a pin below its tip is
       refused however well it links together. */
    {
        kw_headerstore c;
        uint8_t b1[80], b2[80];
        kw_test_unhex(B1_HDR, b1);
        kw_test_unhex(B2_HDR, b2);
        if (!kw_headerstore_init(&c)) { fprintf(stderr, "FAIL: store init\n"); return 1; }
        kw_block_header h1, h2;
        kw_block_header_parse(b1, 80, &h1);
        kw_block_header_parse(b2, 80, &h2);
        if (!kw_headerstore_append(&c, &h1) || !kw_headerstore_append(&c, &h2))
            { fprintf(stderr, "FAIL: could not build a store\n"); return 1; }

        char b1disp[65];
        uint8_t d2[32];
        for (int i = 0; i < 32; i++) d2[i] = h1.hash[31 - i];
        kw_hex_encode(d2, 32, b1disp, sizeof b1disp);

        kw_checkpoint good[2] = { { 1, b1disp }, { 2, B2_DISP } };
        kw_chainparams anchored = KW_DOGE_REGTEST;
        anchored.checkpoints = good;
        anchored.ncheckpoints = 2;
        uint32_t bad = 0;
        if (!kw_sync_anchors_ok(&c, &anchored, &bad))
            { fprintf(stderr, "FAIL: a cache matching its anchors was refused at %u\n", bad); return 1; }

        char bent[65];
        memcpy(bent, b1disp, sizeof bent);
        bent[0] = (bent[0] == 'a') ? 'b' : 'a';
        kw_checkpoint wrong[2] = { { 1, bent }, { 2, B2_DISP } };
        anchored.checkpoints = wrong;
        if (kw_sync_anchors_ok(&c, &anchored, &bad))
            { fprintf(stderr, "FAIL: a cache disagreeing with a pin was accepted\n"); return 1; }
        if (bad != 1) { fprintf(stderr, "FAIL: reported height %u, want 1\n", bad); return 1; }

        /* A KWH2 record carries its own hash and the load believes it, so a store
           whose raw bytes were edited while the stored hash was left alone still
           links. The anchor check hashes the raw header, which is the only way
           that store fails: comparing against the stored hash compares the file
           with itself. */
        anchored.checkpoints = good;
        anchored.ncheckpoints = 2;
        c.h[0].raw[76] ^= 0x01;                  /* the nonce, hash left as it was */
        if (kw_sync_anchors_ok(&c, &anchored, &bad))
            { fprintf(stderr, "FAIL: an edited header passed on its own stored hash\n"); return 1; }
        if (bad != 1) { fprintf(stderr, "FAIL: reported height %u for the edit, want 1\n", bad); return 1; }
        c.h[0].raw[76] ^= 0x01;
        if (!kw_sync_anchors_ok(&c, &anchored, &bad))
            { fprintf(stderr, "FAIL: undoing the edit did not restore the store\n"); return 1; }

        /* an anchor above the tip says nothing about what is below it */
        kw_checkpoint far[1] = { { 9999, B2_DISP } };
        anchored.checkpoints = far;
        anchored.ncheckpoints = 1;
        if (!kw_sync_anchors_ok(&c, &anchored, &bad))
            { fprintf(stderr, "FAIL: an anchor past the tip was treated as a mismatch\n"); return 1; }
        kw_headerstore_free(&c);
    }

    printf("sync ok: two getheaders rounds, blocks 1,2 appended, tip is block 2,\n"
       "  mainnet's first retarget demanded at height 240 and inheritance below it,\n"
       "  anchors enforced on the default path, a chain short of the last one refused,\n"
       "  a cached chain checked against the pins on load by hashing it,\n  and a locator, a work sum and a rollback to choose between chains with\n");
    return 0;
}
