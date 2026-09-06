/* koinu.dog - live BIP157 compact-filter balance tool (not part of `make check`)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 *   make net_cf && ./net_cf [--regtest] host port <address> [address ...]
 *
 * Needs a peer that serves BIP157 (a patched node with the filter index). Syncs
 * headers, pulls a basic filter per block, and downloads only the blocks whose
 * filter matches one of the addresses, printing the resulting UTXO count and
 * balance and the wall time of each phase. */

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
#include <time.h>

static int addr_to_spk(const char *addr, uint8_t spk[25])
{
    uint8_t payload[64]; size_t plen = 0;
    if (!kw_base58check_decode(addr, payload, sizeof payload, &plen) || plen != 21) return 0;
    spk[0] = 0x76; spk[1] = 0xa9; spk[2] = 0x14;
    memcpy(spk + 3, payload + 1, 20);
    spk[23] = 0x88; spk[24] = 0xac;
    return 1;
}

static double since(struct timespec a) {
    struct timespec b; clock_gettime(CLOCK_MONOTONIC, &b);
    return (double)(b.tv_sec - a.tv_sec) + (double)(b.tv_nsec - a.tv_nsec) / 1e9;
}

int main(int argc, char **argv)
{
    const kw_chainparams *cp = &KW_DOGE_MAINNET;
    const char *host = "127.0.0.1";
    const char *addrs[64]; int naddr = 0;
    int port = -1;
    for (int i = 1, seen = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--testnet")) cp = &KW_DOGE_TESTNET;
        else if (!strcmp(argv[i], "--regtest")) cp = &KW_DOGE_REGTEST;
        else if (argv[i][0] == '-') continue;
        else if (seen++ == 0) host = argv[i];
        else if (seen == 2) port = atoi(argv[i]);
        else if (naddr < 64) addrs[naddr++] = argv[i];
    }
    if (port < 0) port = cp->p2p_port;
    if (naddr == 0) { fprintf(stderr, "usage: net_cf [--regtest] host port <address> [address ...]\n"); return 1; }

    kw_net_verbose = 1;
    kw_watchset ws; kw_watchset_init(&ws);
    for (int i = 0; i < naddr; i++) {
        uint8_t spk[25];
        if (!addr_to_spk(addrs[i], spk)) { fprintf(stderr, "bad address %s\n", addrs[i]); return 1; }
        kw_watchset_add(&ws, spk, sizeof spk);
    }

    kw_peer p;
    if (!kw_peer_connect(&p, cp, host, port, 15)) { fprintf(stderr, "connect failed\n"); return 1; }
    if (!kw_peer_handshake(&p, 0)) { fprintf(stderr, "handshake failed\n"); kw_peer_close(&p); return 1; }
    printf("handshake ok, peer height %d, watching %d address(es)\n", p.peer_height, naddr);

    struct timespec t0; clock_gettime(CLOCK_MONOTONIC, &t0);
    kw_headerstore s; kw_headerstore_init(&s);
    long nh = kw_sync_headers(&p, &s, cp);
    if (nh < 0) { fprintf(stderr, "header sync failed\n"); return 1; }
    printf("synced %ld headers in %.1fs\n", nh, since(t0));

    kw_utxoset us; kw_utxoset_init(&us);
    struct timespec t1; clock_gettime(CLOCK_MONOTONIC, &t1);
    long nb = kw_cf_sync(&p, &s, &us, &ws, 1);
    if (nb < 0) { fprintf(stderr, "cf sync failed (does the peer serve BIP157?)\n"); return 1; }
    printf("cf sync in %.1fs: %ld blocks matched and scanned\n", since(t1), nb);

    printf("result: %zu utxos, balance %llu koinu\n",
           kw_utxoset_count(&us), (unsigned long long)kw_utxoset_balance(&us));

    kw_utxoset_free(&us); kw_watchset_free(&ws);
    kw_headerstore_free(&s); kw_peer_close(&p);
    return 0;
}
