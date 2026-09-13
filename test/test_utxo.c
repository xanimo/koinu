/* koinu.dog - UTXO tracking tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * The coinbase is a real Dogecoin regtest coinbase (dogecoin-cli
 * getrawtransaction): it pays 500000 DOGE to msPhefA3jPKEidKjrGvPVfopmzyBH4wUG8
 * in vout[0] and carries a zero-value witness-commitment OP_RETURN in vout[1].
 * The spend is built here over that coinbase's outpoint; scanning ignores
 * scriptSig validity, so it need not be signed. */

#include "utxo.h"
#include "tx.h"
#include "testutil.h"
#include "hex.h"

#include <stdio.h>
#include <string.h>

static const char *CB_RAW =
    "01000000010000000000000000000000000000000000000000000000000000000000000000"
    "ffffffff03510101ffffffff0200203d88792d00001976a91482425f7352322594ecdfd142"
    "573216ec88e9dd3d88ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999df"
    "a36953755c690689799962b48bebd836974e8cf900000000";
static const char *CB_TXID = "ae40fe874a187047a985149639ef8076a91b68b629a019d6189cd346e17512d1";
static const char *CB_SPK  = "76a91482425f7352322594ecdfd142573216ec88e9dd3d88ac";
static const uint64_t CB_VALUE = 50000000000000ULL;

int main(void)
{
    uint8_t cb[512];
    size_t cblen = (size_t)kw_test_unhex(CB_RAW, cb);
    uint8_t spk[64];
    size_t spklen = (size_t)kw_test_unhex(CB_SPK, spk);

    kw_watchset ws;
    if (!kw_watchset_init(&ws) || !kw_watchset_add(&ws, spk, spklen)) {
        fprintf(stderr, "FAIL: watchset\n"); return 1;
    }

    kw_utxoset us;
    if (!kw_utxoset_init(&us)) { fprintf(stderr, "FAIL: utxoset init\n"); return 1; }

    /* the coinbase pays our watched script in vout[0]; vout[1] is an OP_RETURN
       we do not watch. one UTXO, its value, appears. */
    if (!kw_utxoset_apply_tx(&us, &ws, cb, cblen, 1)) { fprintf(stderr, "FAIL: apply coinbase\n"); return 1; }
    if (kw_utxoset_count(&us) != 1) { fprintf(stderr, "FAIL: count %zu\n", kw_utxoset_count(&us)); return 1; }
    if (kw_utxoset_balance(&us) != CB_VALUE) { fprintf(stderr, "FAIL: balance %llu\n",
        (unsigned long long)kw_utxoset_balance(&us)); return 1; }

    /* the stored outpoint is the coinbase txid (internal = reversed display). */
    uint8_t want_id[32], disp[32];
    kw_test_unhex(CB_TXID, disp);
    for (int i = 0; i < 32; i++) want_id[i] = disp[31 - i];
    if (memcmp(us.u[0].txid, want_id, 32) != 0 || us.u[0].vout != 0) {
        fprintf(stderr, "FAIL: outpoint\n"); return 1;
    }

    /* a transaction spending that outpoint removes the UTXO. */
    {
        kw_tx tx;
        kw_tx_init(&tx);
        if (!kw_tx_add_input(&tx, CB_TXID, 0)) { fprintf(stderr, "FAIL: add input\n"); return 1; }
        uint8_t other[20]; memset(other, 0x11, 20);
        if (!kw_tx_add_output_p2pkh(&tx, CB_VALUE - 100000000ULL, other)) {
            fprintf(stderr, "FAIL: add output\n"); return 1;
        }
        uint8_t raw[512];
        size_t n = kw_tx_serialize(&tx, raw, sizeof raw);
        if (!n) { fprintf(stderr, "FAIL: serialize spend\n"); return 1; }
        if (!kw_utxoset_apply_tx(&us, &ws, raw, n, 2)) { fprintf(stderr, "FAIL: apply spend\n"); return 1; }
        if (kw_utxoset_count(&us) != 0 || kw_utxoset_balance(&us) != 0) {
            fprintf(stderr, "FAIL: spend did not clear (count %zu)\n", kw_utxoset_count(&us)); return 1;
        }
    }

    /* an output to an unwatched script adds nothing; one to the watched script
       is tracked again. */
    {
        kw_tx tx;
        kw_tx_init(&tx);
        kw_tx_add_input(&tx, CB_TXID, 0);
        uint8_t other[20]; memset(other, 0x22, 20);
        kw_tx_add_output_p2pkh(&tx, 100000000ULL, other);          /* unwatched */
        kw_tx_add_output(&tx, 200000000ULL, spk, spklen);          /* watched */
        uint8_t raw[512];
        size_t n = kw_tx_serialize(&tx, raw, sizeof raw);
        if (!kw_utxoset_apply_tx(&us, &ws, raw, n, 3)) { fprintf(stderr, "FAIL: apply mixed\n"); return 1; }
        if (kw_utxoset_count(&us) != 1 || kw_utxoset_balance(&us) != 200000000ULL) {
            fprintf(stderr, "FAIL: only watched output tracked (count %zu bal %llu)\n",
                kw_utxoset_count(&us), (unsigned long long)kw_utxoset_balance(&us)); return 1;
        }
        if (us.u[0].vout != 1) { fprintf(stderr, "FAIL: watched output index\n"); return 1; }
    }

    /* a malformed (truncated) transaction is rejected. */
    if (kw_utxoset_apply_tx(&us, &ws, cb, cblen - 5, 4)) { fprintf(stderr, "FAIL: truncated accepted\n"); return 1; }

    /* save and reload preserves the set exactly. */
    {
        const char *tmp = "test_utxo_roundtrip.tmp";
        if (!kw_utxoset_save(&us, tmp)) { fprintf(stderr, "FAIL: save\n"); return 1; }
        kw_utxoset us2; kw_utxoset_init(&us2);
        if (!kw_utxoset_load(&us2, tmp)) { fprintf(stderr, "FAIL: load\n"); return 1; }
        if (kw_utxoset_count(&us2) != kw_utxoset_count(&us) ||
            kw_utxoset_balance(&us2) != kw_utxoset_balance(&us)) { fprintf(stderr, "FAIL: roundtrip totals\n"); return 1; }
        const kw_utxo *a = &us.u[0], *b = &us2.u[0];
        if (memcmp(a->txid, b->txid, 32) || a->vout != b->vout || a->value != b->value ||
            a->height != b->height || a->spklen != b->spklen ||
            memcmp(a->spk, b->spk, a->spklen)) { fprintf(stderr, "FAIL: roundtrip fields\n"); return 1; }
        kw_utxoset_free(&us2);
        remove(tmp);
    }

    kw_utxoset_free(&us);
    kw_watchset_free(&ws);

    /* A value that would carry the total past what a uint64 holds is refused, so no
       later sum of a subset can wrap. Dogecoin issues forever and its supply is
       already 81% of the range, so the headroom is smaller than it looks. */
    {
        kw_utxoset o;
        uint8_t t1[32], t2[32], spk[25] = { 0x76, 0xa9, 0x14 };
        memset(t1, 0x11, 32);
        memset(t2, 0x22, 32);
        if (!kw_utxoset_init(&o)) { fprintf(stderr, "FAIL: init\n"); return 1; }
        if (!kw_utxoset_add(&o, t1, 0, (uint64_t)1 << 63, 100, spk, sizeof spk))
            { fprintf(stderr, "FAIL: a lone huge value should be accepted\n"); return 1; }
        if (kw_utxoset_add(&o, t2, 1, (uint64_t)1 << 63, 101, spk, sizeof spk))
            { fprintf(stderr, "FAIL: a second one wrapped the total and was accepted\n"); return 1; }
        if (kw_utxoset_count(&o) != 1) { fprintf(stderr, "FAIL: the refused entry was stored\n"); return 1; }
        if (kw_utxoset_balance(&o) != ((uint64_t)1 << 63))
            { fprintf(stderr, "FAIL: balance %llu after the refusal\n",
                      (unsigned long long)kw_utxoset_balance(&o)); return 1; }
        /* and room freed by a spend is usable again */
        if (!kw_utxoset_add(&o, t2, 1, 1000, 101, spk, sizeof spk))
            { fprintf(stderr, "FAIL: a value that fits was refused\n"); return 1; }
        kw_utxoset_free(&o);
    }

    printf("utxo ok: real coinbase add, spend removes, watch filter, txid outpoint, truncation, save/load,\n"
           "  and a value that would wrap the total refused\n");
    return 0;
}
