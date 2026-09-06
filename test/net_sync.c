/* koinu.dog - live header sync tool (not part of `make check`)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 *   make net_sync && ./net_sync --regtest 127.0.0.1 18444 */

#include "sync.h"
#include "peer.h"
#include "headers.h"
#include "chainparams.h"
#include "hex.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    const kw_chainparams *cp = &KW_DOGE_MAINNET;
    const char *host = "127.0.0.1";
    int port = -1, tor = 0;
    for (int i = 1, seen = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--testnet")) cp = &KW_DOGE_TESTNET;
        else if (!strcmp(argv[i], "--regtest")) cp = &KW_DOGE_REGTEST;
        else if (!strcmp(argv[i], "--tor")) tor = 1;
        else if (argv[i][0] == '-') continue;
        else if (seen++ == 0) host = argv[i];
        else port = atoi(argv[i]);
    }
    if (port < 0) port = cp->p2p_port;

    kw_peer p;
    int ok = tor ? kw_peer_connect_socks5(&p, cp, host, port, 15, "127.0.0.1", 9050)
                 : kw_peer_connect(&p, cp, host, port, 15);
    if (!ok) { fprintf(stderr, "connect failed\n"); return 1; }
    if (!kw_peer_handshake(&p, 0)) { fprintf(stderr, "handshake failed\n"); kw_peer_close(&p); return 1; }
    printf("handshake ok, peer height %d\n", p.peer_height);

    kw_headerstore s;
    kw_headerstore_init(&s);
    long n = kw_sync_headers(&p, &s, cp);
    if (n < 0) { fprintf(stderr, "sync failed (auxpow header or bad link?)\n"); kw_headerstore_free(&s); kw_peer_close(&p); return 1; }

    const kw_block_header *tip = kw_headerstore_tip(&s);
    char d[65] = "(none)";
    if (tip) { uint8_t r[32]; for (int i = 0; i < 32; i++) r[i] = tip->hash[31-i]; kw_hex_encode(r, 32, d, sizeof d); }
    printf("synced %ld headers, tip %s\n", n, d);

    kw_headerstore_free(&s);
    kw_peer_close(&p);
    return 0;
}
