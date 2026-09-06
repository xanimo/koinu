/* koinu.dog - live BIP157 compact-filter balance tool (not part of `make check`)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 *   make net_cf && ./net_cf --regtest 127.0.0.1 18444 <address>
 *
 * Needs a peer that serves BIP157 (a patched node with the filter index). Syncs
 * headers, pulls a basic filter per block, and downloads only the blocks whose
 * filter matches the address, printing the resulting UTXO count and balance. */

#include "cf.h"
#include "sync.h"
#include "peer.h"
#include "headers.h"
#include "utxo.h"
#include "chainparams.h"
#include "base58.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    const kw_chainparams *cp = &KW_DOGE_MAINNET;
    const char *host = "127.0.0.1";
    const char *addr = NULL;
    int port = -1;
    for (int i = 1, seen = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--testnet")) cp = &KW_DOGE_TESTNET;
        else if (!strcmp(argv[i], "--regtest")) cp = &KW_DOGE_REGTEST;
        else if (argv[i][0] == '-') continue;
        else if (seen++ == 0) host = argv[i];
        else if (seen == 2) port = atoi(argv[i]);
        else addr = argv[i];
    }
    if (port < 0) port = cp->p2p_port;
    if (!addr) { fprintf(stderr, "usage: net_cf [--regtest] host port <address>\n"); return 1; }

    uint8_t payload[64]; size_t plen = 0;
    if (!kw_base58check_decode(addr, payload, sizeof payload, &plen) || plen != 21) {
        fprintf(stderr, "bad address\n"); return 1;
    }
    uint8_t spk[25];
    spk[0] = 0x76; spk[1] = 0xa9; spk[2] = 0x14;
    memcpy(spk + 3, payload + 1, 20);
    spk[23] = 0x88; spk[24] = 0xac;

    kw_peer p;
    if (!kw_peer_connect(&p, cp, host, port, 15)) { fprintf(stderr, "connect failed\n"); return 1; }
    if (!kw_peer_handshake(&p, 0)) { fprintf(stderr, "handshake failed\n"); kw_peer_close(&p); return 1; }

    kw_headerstore s;
    kw_headerstore_init(&s);
    long nh = kw_sync_headers(&p, &s, cp);
    if (nh < 0) { fprintf(stderr, "header sync failed\n"); kw_headerstore_free(&s); kw_peer_close(&p); return 1; }
    printf("synced %ld headers\n", nh);

    kw_watchset ws; kw_watchset_init(&ws); kw_watchset_add(&ws, spk, sizeof spk);
    kw_utxoset us; kw_utxoset_init(&us);

    long nb = kw_cf_sync(&p, &s, &us, &ws, 1);   /* store index 0 is block height 1 */
    if (nb < 0) { fprintf(stderr, "cf sync failed (does the peer serve BIP157?)\n");
        kw_headerstore_free(&s); kw_peer_close(&p); return 1; }

    printf("filter-matched and scanned %ld blocks, %zu utxos, balance %llu koinu\n",
           nb, kw_utxoset_count(&us), (unsigned long long)kw_utxoset_balance(&us));

    kw_utxoset_free(&us); kw_watchset_free(&ws);
    kw_headerstore_free(&s); kw_peer_close(&p);
    return 0;
}
