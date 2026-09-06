/* koinu.dog - SPV block scan and getdata tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * BLOCK_RAW is a real Dogecoin regtest block (dogecoin-cli getblock <h> 0): a
 * coinbase paying 500000.00226 DOGE to mokCsz94... and a spend paying two other
 * addresses. Scanning it while watching mokCsz94...'s script must add exactly
 * the coinbase output. */

#include "spv.h"
#include "utxo.h"
#include "tx.h"
#include "testutil.h"
#include "hex.h"

#include <stdio.h>
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
        memset(blk, 0, KW_HEADER_LEN); n = KW_HEADER_LEN;   /* header ignored by scan */
        blk[n++] = 0x02;                                    /* two transactions */
        memcpy(blk + n, cb, cblen); n += cblen;
        memcpy(blk + n, spend, slen); n += slen;

        kw_watchset ws; kw_watchset_init(&ws); kw_watchset_add(&ws, spk, spklen);
        kw_utxoset us; kw_utxoset_init(&us);
        if (!kw_block_scan(blk, n, &us, &ws, 5)) { fprintf(stderr, "FAIL: scan two-tx block\n"); return 1; }
        if (kw_utxoset_count(&us) != 0 || kw_utxoset_balance(&us) != 0) {
            fprintf(stderr, "FAIL: intra-block spend (count %zu)\n", kw_utxoset_count(&us)); return 1;
        }
        kw_utxoset_free(&us); kw_watchset_free(&ws);
    }

    printf("spv ok: getdata inv, real block scan (coinbase to A), truncation, intra-block spend\n");
    return 0;
}
