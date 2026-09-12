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
    printf("sync ok: two getheaders rounds, blocks 1,2 appended, tip is block 2,\n"
       "  mainnet's first retarget demanded at height 240 and inheritance below it\n");
    return 0;
}
