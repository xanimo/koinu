/* dogewallet - peer transport and handshake (offline, over a socketpair)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * A socketpair stands in for the network: we pre-load the "peer" end with a
 * version and verack, run our handshake on the near end, then confirm what we
 * sent and that recv reassembles a following message. A live handshake against
 * a real node is test/net_handshake.c, run by hand. */

#include "peer.h"
#include "proto.h"
#include "msg.h"
#include "chainparams.h"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

int main(void)
{
    uint32_t magic = DW_DOGE_REGTEST.magic;
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { fprintf(stderr, "FAIL: socketpair\n"); return 1; }
    struct timeval tv = { 5, 0 };
    setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(sv[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    /* preload the peer end: its version (height 800000) then verack */
    dw_msg_version pv;
    memset(&pv, 0, sizeof pv);
    pv.version = 70015; pv.services = 1; pv.timestamp = 1700000000;
    dw_netaddr_ipv4(pv.recv_ip, 0,0,0,0); dw_netaddr_ipv4(pv.from_ip, 0,0,0,0);
    pv.nonce = 0x1111222233334444ULL; pv.user_agent = "/core:1.14/";
    pv.start_height = 800000; pv.relay = 1;
    uint8_t body[256]; size_t bl = dw_msg_version_build(&pv, body, sizeof body);
    uint8_t frame[512]; size_t fn;
    fn = dw_msg_serialize(magic, "version", body, bl, frame, sizeof frame);
    if (write(sv[1], frame, fn) != (ssize_t)fn) { fprintf(stderr, "FAIL: preload version\n"); return 1; }
    fn = dw_msg_serialize(magic, "verack", NULL, 0, frame, sizeof frame);
    if (write(sv[1], frame, fn) != (ssize_t)fn) { fprintf(stderr, "FAIL: preload verack\n"); return 1; }

    /* run our handshake on the near end */
    dw_peer p;
    dw_peer_from_fd(&p, magic, sv[0]);
    if (!dw_peer_handshake(&p, 12345)) { fprintf(stderr, "FAIL: handshake\n"); return 1; }
    if (p.peer_version != 70015 || p.peer_height != 800000) {
        fprintf(stderr, "FAIL: peer fields (v=%d h=%d)\n", p.peer_version, p.peer_height); return 1;
    }

    /* confirm what we sent the peer: version then verack */
    uint8_t inbuf[1024];
    ssize_t got = read(sv[1], inbuf, sizeof inbuf);
    if (got <= 0) { fprintf(stderr, "FAIL: read back our messages\n"); return 1; }
    char cmd[13]; const uint8_t *pl; size_t pn;
    int c1 = dw_msg_parse(magic, inbuf, (size_t)got, cmd, &pl, &pn);
    if (c1 <= 0 || strcmp(cmd, "version") != 0) { fprintf(stderr, "FAIL: we did not send version\n"); return 1; }
    int c2 = dw_msg_parse(magic, inbuf + c1, (size_t)got - c1, cmd, &pl, &pn);
    if (c2 <= 0 || strcmp(cmd, "verack") != 0) { fprintf(stderr, "FAIL: we did not send verack\n"); return 1; }

    /* a following message reassembles through recv */
    uint8_t nonce[8] = {9,9,9,9,0,0,0,0};
    fn = dw_msg_serialize(magic, "ping", nonce, sizeof nonce, frame, sizeof frame);
    if (write(sv[1], frame, fn) != (ssize_t)fn) { fprintf(stderr, "FAIL: write ping\n"); return 1; }
    if (dw_peer_recv(&p, cmd, &pl, &pn) != 1 || strcmp(cmd, "ping") != 0 || pn != 8 ||
        memcmp(pl, nonce, 8) != 0) { fprintf(stderr, "FAIL: recv ping\n"); return 1; }

    dw_peer_close(&p);
    close(sv[1]);
    printf("peer ok: handshake over a socketpair, sent version+verack, recv reassembles\n");
    return 0;
}
