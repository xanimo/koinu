/* koinu.dog - live handshake tool (not part of `make check`)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Connects to a node and completes the version/verack handshake, printing what
 * the peer advertised. Run against a regtest node by hand:
 *   make net_handshake && ./net_handshake --regtest 127.0.0.1 18444 */

#include "peer.h"
#include "chainparams.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    const kw_chainparams *cp = &KW_DOGE_MAINNET;
    const char *host = "127.0.0.1";
    int port = -1;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--testnet")) cp = &KW_DOGE_TESTNET;
        else if (!strcmp(argv[i], "--regtest")) cp = &KW_DOGE_REGTEST;
        else if (argv[i][0] != '-' && host == NULL) host = argv[i];
        else if (argv[i][0] != '-' && port < 0) { /* first non-flag is host */
            host = argv[i];
        }
    }
    /* positional: [host] [port] after flags */
    for (int i = 1, seen = 0; i < argc; i++) {
        if (argv[i][0] == '-') continue;
        if (seen == 0) { host = argv[i]; seen = 1; }
        else if (seen == 1) { port = atoi(argv[i]); seen = 2; }
    }
    if (port < 0) port = cp->p2p_port;

    kw_peer p;
    if (!kw_peer_connect(&p, cp, host, port, 10)) {
        fprintf(stderr, "connect to %s:%d failed\n", host, port);
        return 1;
    }
    if (!kw_peer_handshake(&p, 0)) {
        fprintf(stderr, "handshake failed\n");
        kw_peer_close(&p);
        return 1;
    }
    printf("handshake ok with %s:%d  peer version %d, height %d\n",
           host, port, p.peer_version, p.peer_height);
    kw_peer_close(&p);
    return 0;
}
