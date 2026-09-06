/* koinu.dog - p2p framing tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "proto.h"
#include "chainparams.h"
#include "testutil.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    uint8_t out[64];

    /* A mainnet verack: magic, "verack" padded to 12, zero length, and the
       checksum of the empty payload (hash256("")[:4] = 5df6e0e2). */
    size_t n = kw_msg_serialize(KW_DOGE_MAINNET.magic, "verack", NULL, 0, out, sizeof out);
    if (n != 24) { fprintf(stderr, "FAIL: verack length %zu\n", n); return 1; }
    kw_test_check("verack frame", out, 24,
        "c0c0c0c076657261636b00000000000000000000" "5df6e0e2");

    /* parse it back */
    char cmd[13]; const uint8_t *pl = NULL; size_t plen = 0;
    int c = kw_msg_parse(KW_DOGE_MAINNET.magic, out, n, cmd, &pl, &plen);
    if (c != 24 || strcmp(cmd, "verack") != 0 || plen != 0) {
        fprintf(stderr, "FAIL: parse verack (c=%d cmd=%s plen=%zu)\n", c, cmd, plen); return 1;
    }

    /* a ping with an 8-byte nonce round-trips */
    uint8_t nonce[8] = {1,2,3,4,5,6,7,8};
    n = kw_msg_serialize(KW_DOGE_MAINNET.magic, "ping", nonce, sizeof nonce, out, sizeof out);
    c = kw_msg_parse(KW_DOGE_MAINNET.magic, out, n, cmd, &pl, &plen);
    if (c != (int)n || strcmp(cmd, "ping") != 0 || plen != 8 || memcmp(pl, nonce, 8) != 0) {
        fprintf(stderr, "FAIL: ping round trip\n"); return 1;
    }

    /* wrong magic is rejected */
    if (kw_msg_parse(KW_DOGE_TESTNET.magic, out, n, cmd, &pl, &plen) != -1) {
        fprintf(stderr, "FAIL: wrong magic accepted\n"); return 1;
    }

    /* a corrupted checksum is rejected */
    { uint8_t t[64]; memcpy(t, out, n); t[20] ^= 1;
      if (kw_msg_parse(KW_DOGE_MAINNET.magic, t, n, cmd, &pl, &plen) != -1) {
          fprintf(stderr, "FAIL: bad checksum accepted\n"); return 1; } }

    /* a header-only prefix asks for more, not an error */
    if (kw_msg_parse(KW_DOGE_MAINNET.magic, out, 23, cmd, &pl, &plen) != 0) {
        fprintf(stderr, "FAIL: short buffer not reported as incomplete\n"); return 1;
    }
    /* a full header promising a body we do not have yet also asks for more */
    if (kw_msg_parse(KW_DOGE_MAINNET.magic, out, KW_MSG_HDR, cmd, &pl, &plen) != 0) {
        fprintf(stderr, "FAIL: missing payload not reported as incomplete\n"); return 1;
    }

    /* the message-start bytes must go out in Dogecoin's wire order, not
       byte-reversed: testnet fc c1 b7 dc, regtest fa bf b5 da */
    n = kw_msg_serialize(KW_DOGE_TESTNET.magic, "verack", NULL, 0, out, sizeof out);
    if (out[0]!=0xfc || out[1]!=0xc1 || out[2]!=0xb7 || out[3]!=0xdc) {
        fprintf(stderr, "FAIL: testnet magic bytes\n"); return 1;
    }
    n = kw_msg_serialize(KW_DOGE_REGTEST.magic, "verack", NULL, 0, out, sizeof out);
    if (out[0]!=0xfa || out[1]!=0xbf || out[2]!=0xb5 || out[3]!=0xda) {
        fprintf(stderr, "FAIL: regtest magic bytes\n"); return 1;
    }

    printf("proto ok: verack vector, ping round trip, magic order, checksum/partial handling\n");
    return 0;
}
