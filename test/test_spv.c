/* koinu.dog - SPV block scan and getdata tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * BLOCK_RAW is a real Dogecoin regtest block (dogecoin-cli getblock <h> 0): a
 * coinbase paying 500000.00226 DOGE to mokCsz94... and a spend paying two other
 * addresses. Scanning it while watching mokCsz94...'s script must add exactly
 * the coinbase output. */

#include "spv.h"
#include "sha2.h"
#include "utxo.h"
#include "tx.h"
#include "testutil.h"
#include "hex.h"

#include "auxpow_block_vector.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *BLOCK_RAW =
    "04006200a5d4112385a5336d511d9ada1db8dc62bf215e9ce9fbbbba983b6fa1f6befb92"
    "552334fa8216f41a95b838e5934aba3cd4edcc62be1b876870c11154bdc9d03458ff9c6a"
    "ffff7f200000000002010000000100000000000000000000000000000000000000000000"
    "00000000000000000000ffffffff0401660101ffffffff02d0924088792d00001976a914"
    "5a4296b815919e8ad0653f3477eef6b1ad3ed55288ac0000000000000000266a24aa21a9"
    "ed872b61081f44c4680761306cf8e020254b5659e73a5089e07227b667fd5fa485000000"
    "00010000000175e0bbc96f01f07ca96a3cd8e9fea3f37854d8cf6acd16bcafd7def590b3"
    "f52d000000006a47304402204b406e0893a4e8687bb05e86644bec230347bed3406e0a87"
    "beb51fdf88909aa802205f9656e9a60f462b1135af3b2f81ead8c1f1a4ca06e682b62e61"
    "df25347a6af0012102ed8dfab46a61867b0fe83a5a520f405a1555fc69e0256a4590886b"
    "edee273b0afeffffff02b02a08ca5c2d00001976a91477a62db2789f7f8118899d0bb057"
    "dd06659193f788ac808231be1c0000001976a914f6eff2e7537a16fa607324c917b1b6e6"
    "492a82ff88ac65000000";
static const char *BLOCK_SPK = "76a9145a4296b815919e8ad0653f3477eef6b1ad3ed55288ac";
static const uint64_t BLOCK_A_VALUE = 50000000226000ULL;

/* a self-contained coinbase paying 82425f...; used to build a two-tx block. */
static const char *CB_RAW =
    "01000000010000000000000000000000000000000000000000000000000000000000000000"
    "ffffffff03510101ffffffff0200203d88792d00001976a91482425f7352322594ecdfd142"
    "573216ec88e9dd3d88ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999df"
    "a36953755c690689799962b48bebd836974e8cf900000000";
static const char *CB_TXID = "ae40fe874a187047a985149639ef8076a91b68b629a019d6189cd346e17512d1";
static const char *CB_SPK  = "76a91482425f7352322594ecdfd142573216ec88e9dd3d88ac";

int main(void)
{
    /* getdata for two blocks: count, then (MSG_BLOCK, hash) each */
    {
        uint8_t h0[32], h1[32];
        memset(h0, 0xa1, 32); memset(h1, 0xb2, 32);
        uint8_t hs[2][32];
        memcpy(hs[0], h0, 32); memcpy(hs[1], h1, 32);
        uint8_t out[128];
        size_t n = kw_msg_getdata_blocks_build(hs, 2, out, sizeof out);
        if (n != 1 + 2 * (4 + 32)) { fprintf(stderr, "FAIL: getdata len %zu\n", n); return 1; }
        if (out[0] != 0x02 || out[1] != 0x02 || out[2] || out[3] || out[4]) {
            fprintf(stderr, "FAIL: getdata inv header\n"); return 1;
        }
        if (memcmp(out + 5, h0, 32) != 0 || memcmp(out + 5 + 32 + 4, h1, 32) != 0) {
            fprintf(stderr, "FAIL: getdata hashes\n"); return 1;
        }
    }

    /* scan the real block: only the coinbase pays our watched script. */
    {
        uint8_t blk[1024];
        size_t blen = (size_t)kw_test_unhex(BLOCK_RAW, blk);
        uint8_t spk[64];
        size_t spklen = (size_t)kw_test_unhex(BLOCK_SPK, spk);

        kw_watchset ws; kw_watchset_init(&ws); kw_watchset_add(&ws, spk, spklen);
        kw_utxoset us; kw_utxoset_init(&us);

        if (!kw_block_scan(blk, blen, &us, &ws, 102)) { fprintf(stderr, "FAIL: scan block\n"); return 1; }
        if (kw_utxoset_count(&us) != 1 || kw_utxoset_balance(&us) != BLOCK_A_VALUE) {
            fprintf(stderr, "FAIL: block balance (count %zu bal %llu)\n",
                kw_utxoset_count(&us), (unsigned long long)kw_utxoset_balance(&us)); return 1;
        }
        if (us.u[0].height != 102) { fprintf(stderr, "FAIL: height not tagged\n"); return 1; }

        /* a truncated block is rejected. */
        if (kw_block_scan(blk, blen - 3, &us, &ws, 102)) { fprintf(stderr, "FAIL: truncated block\n"); return 1; }

        kw_utxoset_free(&us); kw_watchset_free(&ws);
    }

    /* a two-tx block where tx2 spends tx1's coinbase output: walking both, the
       intra-block spend clears the utxo the coinbase added. */
    {
        uint8_t cb[512];
        size_t cblen = (size_t)kw_test_unhex(CB_RAW, cb);
        uint8_t spk[64];
        size_t spklen = (size_t)kw_test_unhex(CB_SPK, spk);

        kw_tx tx; kw_tx_init(&tx);
        kw_tx_add_input(&tx, CB_TXID, 0);
        uint8_t other[20]; memset(other, 0x11, 20);
        kw_tx_add_output_p2pkh(&tx, 1000000000ULL, other);
        uint8_t spend[512];
        size_t slen = kw_tx_serialize(&tx, spend, sizeof spend);

        uint8_t blk[2048]; size_t n = 0;
        memset(blk, 0, KW_HEADER_LEN); n = KW_HEADER_LEN;
        blk[n++] = 0x02;                                    /* two transactions */
        memcpy(blk + n, cb, cblen); n += cblen;
        memcpy(blk + n, spend, slen); n += slen;

        /* The header has to commit to those two, because the scanner now refuses a
           body that does not hash to the root above it. This fixture used to leave
           the root zeroed, which is a block no node would serve. */
        {
            uint8_t t1[32], t2[32], cat[64];
            kw_hash256(cb, cblen, t1);
            kw_hash256(spend, slen, t2);
            memcpy(cat, t1, 32); memcpy(cat + 32, t2, 32);
            kw_hash256(cat, 64, blk + 36);
        }

        kw_watchset ws; kw_watchset_init(&ws); kw_watchset_add(&ws, spk, spklen);
        kw_utxoset us; kw_utxoset_init(&us);
        if (!kw_block_scan(blk, n, &us, &ws, 5)) { fprintf(stderr, "FAIL: scan two-tx block\n"); return 1; }
        if (kw_utxoset_count(&us) != 0 || kw_utxoset_balance(&us) != 0) {
            fprintf(stderr, "FAIL: intra-block spend (count %zu)\n", kw_utxoset_count(&us)); return 1;
        }
        kw_utxoset_free(&us); kw_watchset_free(&ws);
    }

    /* a real mainnet AuxPoW block: its merged-mining blob sits between the header
       and the tx count, so the scan must skip it to reach the transactions. */
    {
        size_t hexlen = strlen(KW_AUXPOW_BLOCK_RAW);
        uint8_t *blk = (uint8_t *)malloc(hexlen / 2);
        if (!blk) { fprintf(stderr, "FAIL: alloc\n"); return 1; }
        int blen = kw_test_unhex(KW_AUXPOW_BLOCK_RAW, blk);
        if (blen <= 0) { fprintf(stderr, "FAIL: auxpow block hex\n"); return 1; }

        uint8_t spk[64];
        int spklen = kw_test_unhex(KW_AUXPOW_BLOCK_SPK, spk);
        kw_watchset ws; kw_watchset_init(&ws); kw_watchset_add(&ws, spk, (size_t)spklen);
        kw_utxoset us; kw_utxoset_init(&us);

        if (!kw_block_scan(blk, (size_t)blen, &us, &ws, KW_AUXPOW_BLOCK_HEIGHT)) {
            fprintf(stderr, "FAIL: scan auxpow block\n"); return 1;
        }
        if (kw_utxoset_count(&us) != 1 || kw_utxoset_balance(&us) != KW_AUXPOW_BLOCK_VALUE) {
            fprintf(stderr, "FAIL: auxpow block value (count %zu bal %llu)\n",
                kw_utxoset_count(&us), (unsigned long long)kw_utxoset_balance(&us)); return 1;
        }
        if (us.u[0].height != KW_AUXPOW_BLOCK_HEIGHT) { fprintf(stderr, "FAIL: auxpow height\n"); return 1; }

        kw_utxoset_free(&us); kw_watchset_free(&ws); free(blk);
    }

    /* find_outpoint on the real auxpow block: it creates DGYr's vout 0 and
       spends nothing of it. */
    {
        size_t hexlen = strlen(KW_AUXPOW_BLOCK_RAW);
        uint8_t *blk = (uint8_t *)malloc(hexlen / 2);
        int blen = kw_test_unhex(KW_AUXPOW_BLOCK_RAW, blk);
        uint8_t tdisp[32], tint[32];
        kw_test_unhex("6e0eefe21280e22aa55fa1709a890516a06e29be89a2e505c4f303f97c10c0b3", tdisp);
        for (int i = 0; i < 32; i++) tint[i] = tdisp[31 - i];

        kw_outpoint_status st = { 0, 0, 0 };
        if (!kw_block_find_outpoint(blk, (size_t)blen, tint, 0, &st) ||
            !st.created || st.created_value != KW_AUXPOW_BLOCK_VALUE || st.spent) {
            fprintf(stderr, "FAIL: find_outpoint created\n"); return 1;
        }
        kw_outpoint_status st2 = { 0, 0, 0 };            /* wrong vout: not created */
        kw_block_find_outpoint(blk, (size_t)blen, tint, 9, &st2);
        if (st2.created || st2.spent) { fprintf(stderr, "FAIL: find_outpoint bogus vout\n"); return 1; }
        free(blk);
    }


    /* A header commits to its transactions and nothing was checking that it did, so a
       peer could serve a genuine header, bound to the verified chain by its hash, with
       any body it liked behind it. That is not a wrong balance: kw outpoint is what a
       merchant ships against, and a fabricated output reported as confirmed is goods
       gone for a transaction that never existed. */
    {
        uint8_t spk2[25] = { 0x76, 0xa9, 0x14 };
        memset(spk2 + 3, 0x42, 20);
        spk2[23] = 0x88; spk2[24] = 0xac;

        /* one invented transaction behind a header that commits to nothing */
        uint8_t blk[512];
        size_t n = 0;
        memset(blk, 0, sizeof blk);
        blk[0] = 1;
        n = KW_HEADER_LEN;
        blk[n++] = 1;
        size_t txat = n;
        kw_tx t;
        kw_tx_init(&t);
        kw_tx_add_input(&t, "00000000000000000000000000000000000000000000000000000000000000ff", 0);
        uint8_t h20[20]; memset(h20, 0x42, 20);
        kw_tx_add_output_p2pkh(&t, 500000000000ULL, h20);
        size_t tl = kw_tx_serialize(&t, blk + n, sizeof blk - n);
        if (!tl) { fprintf(stderr, "FAIL: could not build the fabricated tx\n"); return 1; }
        n += tl;

        kw_watchset w2; kw_watchset_init(&w2); kw_watchset_add(&w2, spk2, 25);
        kw_utxoset u2; kw_utxoset_init(&u2);
        if (kw_block_merkle_ok(blk, n)) { fprintf(stderr, "FAIL: a body its header does not commit to passed\n"); return 1; }
        if (kw_block_scan(blk, n, &u2, &w2, 900)) { fprintf(stderr, "FAIL: the scanner took a fabricated body\n"); return 1; }
        if (kw_utxoset_count(&u2) != 0) { fprintf(stderr, "FAIL: invented coins were credited\n"); return 1; }

        uint8_t ftxid[32];
        kw_hash256(blk + txat, tl, ftxid);
        kw_outpoint_status fst;
        memset(&fst, 0, sizeof fst);
        if (kw_block_find_outpoint(blk, n, ftxid, 0, &fst) || fst.created)
            { fprintf(stderr, "FAIL: a fabricated outpoint was reported as present\n"); return 1; }

        /* and with the real root in place it is accepted, so the check is about the
           commitment rather than about refusing everything */
        kw_hash256(blk + txat, tl, blk + 36);
        if (!kw_block_merkle_ok(blk, n)) { fprintf(stderr, "FAIL: an honest single-tx block was refused\n"); return 1; }

        /* CVE-2012-2459. An odd level duplicates its last node, so [a,b,c] and
           [a,b,c,c] hash to the same root: the second is a different transaction list
           the header commits to just as well. Rejected on the repeated pair, since the
           root cannot say which list it came from.

           Built as three distinct transactions and then a fourth copying the third,
           with the honest root in both headers. Comparing against a zeroed root would
           pass for the wrong reason. */
        {
            uint8_t body[3][256];
            size_t bl[3];
            uint8_t roots[3][32];
            for (int q = 0; q < 3; q++) {
                kw_tx x;
                kw_tx_init(&x);
                kw_tx_add_input(&x, "00000000000000000000000000000000000000000000000000000000000000ff", (uint32_t)q);
                kw_tx_add_output_p2pkh(&x, 1000000ULL + (uint64_t)q, h20);
                bl[q] = kw_tx_serialize(&x, body[q], sizeof body[q]);
                if (!bl[q]) { fprintf(stderr, "FAIL: build tx %d\n", q); return 1; }
                kw_hash256(body[q], bl[q], roots[q]);
            }
            /* the honest root over three: H(H(ab) | H(cc)) */
            uint8_t cat[64], ab[32], cc[32], honest[32];
            memcpy(cat, roots[0], 32); memcpy(cat + 32, roots[1], 32);
            kw_hash256(cat, 64, ab);
            memcpy(cat, roots[2], 32); memcpy(cat + 32, roots[2], 32);
            kw_hash256(cat, 64, cc);
            memcpy(cat, ab, 32); memcpy(cat + 32, cc, 32);
            kw_hash256(cat, 64, honest);

            uint8_t three[1024], four[1024];
            size_t t3 = KW_HEADER_LEN, t4 = KW_HEADER_LEN;
            memset(three, 0, sizeof three); memset(four, 0, sizeof four);
            three[0] = 1; four[0] = 1;
            memcpy(three + 36, honest, 32);
            memcpy(four + 36, honest, 32);
            three[t3++] = 3;
            four[t4++] = 4;
            for (int q = 0; q < 3; q++) { memcpy(three + t3, body[q], bl[q]); t3 += bl[q]; }
            for (int q = 0; q < 3; q++) { memcpy(four + t4, body[q], bl[q]); t4 += bl[q]; }
            memcpy(four + t4, body[2], bl[2]); t4 += bl[2];      /* the last, again */

            if (!kw_block_merkle_ok(three, t3))
                { fprintf(stderr, "FAIL: the honest three-transaction block was refused\n"); return 1; }
            if (kw_block_merkle_ok(four, t4))
                { fprintf(stderr, "FAIL: a repeated last transaction hashed to the same root and passed\n"); return 1; }
        }

        kw_utxoset_free(&u2); kw_watchset_free(&w2);
    }

    printf("spv ok: getdata inv, block scan, auxpow skip, intra-block spend, find_outpoint,\n"
           "  a body its header does not commit to refused, and a repeated last node with it\n");
    return 0;
}
