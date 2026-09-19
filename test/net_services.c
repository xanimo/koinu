/* koinu.dog - what the network actually offers
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Build on demand. Resolves the chain's dns seeds, shakes hands with each peer and
 * prints the service bits it advertises. It exists to answer one question with a
 * number rather than an impression: how many reachable mainnet peers serve bip158
 * compact filters, which is what the default scan backend and kwd both need. */

#include "chainparams.h"
#include "msg.h"
#include "peer.h"
#include "proto.h"
#include "seed.h"

#include <stdio.h>
#include <string.h>

#define NODE_NETWORK         (1ULL << 0)
#define NODE_BLOOM           (1ULL << 2)
#define NODE_WITNESS         (1ULL << 3)
#define NODE_COMPACT_FILTERS (1ULL << 6)
#define NODE_NETWORK_LIMITED (1ULL << 10)

/* A handshake that keeps the peer's advertised services, which kw_peer_handshake
   reads and drops. Same exchange otherwise. */
static int shake(kw_peer *p, const kw_chainparams *cp, uint64_t *services, char *ua, size_t uacap)
{
    kw_msg_version v;
    memset(&v, 0, sizeof v);
    v.version = KW_PROTOCOL_VERSION;
    v.timestamp = 1700000000;
    kw_netaddr_ipv4(v.recv_ip, 0, 0, 0, 0);
    kw_netaddr_ipv4(v.from_ip, 0, 0, 0, 0);
    v.nonce = 0x2222333344445555ULL;
    v.user_agent = "/koinu-probe:0/";
    v.relay = 0;

    uint8_t body[256];
    size_t bl = kw_msg_version_build(&v, body, sizeof body);
    if (!bl || !kw_peer_send(p, "version", body, bl)) return 0;

    int got_version = 0, got_verack = 0;
    for (int i = 0; i < 32 && !got_verack; i++) {
        char cmd[13]; const uint8_t *pl = NULL; size_t pn = 0;
        if (kw_peer_recv(p, cmd, &pl, &pn) != 1) return 0;
        if (!strcmp(cmd, "version")) {
            kw_msg_version pv;
            char buf[256];
            if (kw_msg_version_parse(pl, pn, &pv, buf, sizeof buf)) {
                *services = pv.services;
                snprintf(ua, uacap, "%s", buf);
                got_version = 1;
            }
            kw_peer_send(p, "verack", NULL, 0);
        } else if (!strcmp(cmd, "verack")) {
            got_verack = 1;
        } else if (!strcmp(cmd, "ping")) {
            kw_peer_send(p, "pong", pl, pn);
        }
    }
    return got_version;
}

int main(int argc, char **argv)
{
    const kw_chainparams *cp = &KW_DOGE_MAINNET;
    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "--testnet")) cp = &KW_DOGE_TESTNET;

    char addrs[64][KW_SEED_ADDRLEN];
    size_t n = kw_seed_resolve(cp, addrs, 64);
    printf("%zu peers from the dns seeds\n\n", n);

    int reached = 0, filters = 0;
    for (size_t i = 0; i < n; i++) {
        kw_peer p;
        if (!kw_peer_connect(&p, cp, addrs[i], cp->p2p_port, 5)) continue;
        uint64_t sv = 0;
        char ua[256] = "";
        if (shake(&p, cp, &sv, ua, sizeof ua)) {
            reached++;
            int cf = (sv & NODE_COMPACT_FILTERS) != 0;
            if (cf) filters++;
            printf("%-16s services %#llx%s%s%s%s  %s\n", addrs[i],
                   (unsigned long long)sv,
                   (sv & NODE_NETWORK) ? " network" : "",
                   (sv & NODE_BLOOM) ? " bloom" : "",
                   (sv & NODE_WITNESS) ? " witness" : "",
                   cf ? " COMPACT_FILTERS" : "",
                   ua);
        }
        kw_peer_close(&p);
    }

    printf("\n%d of %zu reachable, %d serve compact filters\n", reached, n, filters);
    return 0;
}
