/* koinu.dog - live P2SH 2-of-2 co-sign harness (not part of `make check`)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Two fixed keys form a 2-of-2 redeem script. `addr` prints the P2SH address to
 * fund; `sign TXID VOUT AMOUNT DEST FEE` (amounts in koinu) builds a spend of
 * that funding output, signs with both keys, assembles the redeeming scriptSig,
 * and prints the raw transaction for a node to accept. */

#include "chainparams.h"
#include "tx.h"
#include "ec.h"
#include "base58.h"
#include "ripemd160.h"
#include "hex.h"
#include "mem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const kw_chainparams *chain_for(int net)
{
    if (net == 1) return &KW_DOGE_TESTNET;
    if (net == 2) return &KW_DOGE_REGTEST;
    return &KW_DOGE_MAINNET;
}

int main(int argc, char **argv)
{
    int net = 0;
    const char *pos[8]; int np = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--testnet")) net = 1;
        else if (!strcmp(argv[i], "--regtest")) net = 2;
        else if (argv[i][0] != '-' && np < 8) pos[np++] = argv[i];
    }
    if (np < 1) { fprintf(stderr, "usage: net_multisig [--regtest] addr | sign TXID VOUT AMOUNT DEST FEE\n"); return 2; }

    kw_ec_start();
    const kw_chainparams *cp = chain_for(net);

    uint8_t sk1[32], sk2[32]; memset(sk1, 0x11, 32); memset(sk2, 0x22, 32);
    uint8_t pub1[33], pub2[33];
    kw_ec_pubkey(sk1, pub1); kw_ec_pubkey(sk2, pub2);
    uint8_t keys[2][33]; memcpy(keys[0], pub1, 33); memcpy(keys[1], pub2, 33);
    uint8_t redeem[128];
    size_t rl = kw_script_multisig(2, keys, 2, redeem, sizeof redeem);
    uint8_t h160[20]; kw_hash160(redeem, rl, h160);

    int rc = 1;
    if (!strcmp(pos[0], "addr")) {
        uint8_t pay[21]; pay[0] = cp->p2sh; memcpy(pay + 1, h160, 20);
        char addr[64];
        if (kw_base58check_encode(pay, 21, addr, sizeof addr)) { printf("%s\n", addr); rc = 0; }
    } else if (!strcmp(pos[0], "sign") && np == 6) {
        const char *txid = pos[1];
        uint32_t vout = (uint32_t)strtoul(pos[2], NULL, 10);
        uint64_t amount = strtoull(pos[3], NULL, 10);
        const char *dest = pos[4];
        uint64_t fee = strtoull(pos[5], NULL, 10);

        kw_tx tx; kw_tx_init(&tx);
        if (!kw_tx_add_input(&tx, txid, vout)) { fprintf(stderr, "bad txid\n"); goto out; }

        uint8_t pay[64]; size_t pl = 0;
        if (!kw_base58check_decode(dest, pay, sizeof pay, &pl) || pl != 21) { fprintf(stderr, "bad dest\n"); goto out; }
        uint8_t dspk[25]; size_t dl = 0;
        if (pay[0] == cp->p2pkh) { dspk[0]=0x76;dspk[1]=0xa9;dspk[2]=0x14; memcpy(dspk+3,pay+1,20); dspk[23]=0x88;dspk[24]=0xac; dl=25; }
        else if (pay[0] == cp->p2sh) { dspk[0]=0xa9;dspk[1]=0x14; memcpy(dspk+2,pay+1,20); dspk[22]=0x87; dl=23; }
        else { fprintf(stderr, "dest not this network\n"); goto out; }
        if (amount <= fee) { fprintf(stderr, "amount <= fee\n"); goto out; }
        kw_tx_add_output(&tx, amount - fee, dspk, dl);

        uint8_t sigA[73], sigB[73]; size_t la = sizeof sigA, lb = sizeof sigB;
        if (!kw_tx_signature(&tx, 0, sk1, redeem, rl, KW_SIGHASH_ALL, sigA, &la) ||
            !kw_tx_signature(&tx, 0, sk2, redeem, rl, KW_SIGHASH_ALL, sigB, &lb)) { fprintf(stderr, "sign failed\n"); goto out; }
        const uint8_t *sigs[2] = { sigA, sigB }; size_t lens[2] = { la, lb };
        if (!kw_tx_set_multisig(&tx, 0, sigs, lens, 2, redeem, rl)) { fprintf(stderr, "assemble failed\n"); goto out; }

        uint8_t raw[16384];
        size_t rn = kw_tx_serialize(&tx, raw, sizeof raw);
        if (!rn) { fprintf(stderr, "serialize failed\n"); goto out; }
        char hex[32770]; kw_hex_encode(raw, rn, hex, sizeof hex);
        printf("%s\n", hex);
        rc = 0;
    } else fprintf(stderr, "bad args\n");

out:
    kw_ec_stop();
    return rc;
}
