/* koinu.dog - transaction signing test
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * The expected signed transaction was produced by libdogecoin's
 * sign_raw_transaction_ex for the same key and inputs. Both sign with RFC 6979
 * deterministic, low-S ECDSA, so a correct legacy sighash reproduces the exact
 * bytes. A 1-in/1-out P2PKH spend, SIGHASH_ALL. */

#include "tx.h"
#include "address.h"
#include "ripemd160.h"
#include "ec.h"
#include "hex.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    if (!kw_ec_start()) { fprintf(stderr, "FAIL ec_start\n"); return 1; }

    /* the mainnet key whose address anchors test_address */
    uint8_t sk[32], pub[33], h160[20];
    int comp; uint8_t ver;
    if (!kw_wif_decode("QPbCXTPCJU3NRPLGbVYjXRYw1WcFFQ6apxiUNRP4bSDQCojDfLpv", sk, &comp, &ver)) {
        fprintf(stderr, "FAIL wif\n"); return 1;
    }
    kw_ec_pubkey(sk, pub);
    kw_hash160(pub, 33, h160);
    char h160hex[41]; kw_hex_encode(h160, 20, h160hex, sizeof h160hex);
    if (strcmp(h160hex, "0e2e16cdd3940acc48f784ee26779709dcd72273") != 0) {
        fprintf(stderr, "FAIL hash160 %s\n", h160hex); return 1;
    }

    uint8_t spk[25];
    spk[0]=0x76; spk[1]=0xa9; spk[2]=0x14; memcpy(spk+3, h160, 20); spk[23]=0x88; spk[24]=0xac;

    kw_tx tx;
    kw_tx_init(&tx);
    if (!kw_tx_add_input(&tx, "0000000000000000000000000000000000000000000000000000000000000001", 0)) {
        fprintf(stderr, "FAIL add_input\n"); return 1;
    }
    if (!kw_tx_add_output_p2pkh(&tx, 100000000ULL, h160)) { fprintf(stderr, "FAIL add_output\n"); return 1; }
    if (!kw_tx_sign_p2pkh(&tx, 0, sk, spk, sizeof spk)) { fprintf(stderr, "FAIL sign\n"); return 1; }

    uint8_t raw[1024];
    size_t n = kw_tx_serialize(&tx, raw, sizeof raw);
    if (!n) { fprintf(stderr, "FAIL serialize\n"); return 1; }
    char got[2048]; kw_hex_encode(raw, n, got, sizeof got);

    const char *want =
        "01000000010100000000000000000000000000000000000000000000000000000000000000"
        "000000006a473044022038ceab2e6a99ab0fbf062144950d123d970fbd3892d11b51d771ed5"
        "906f892eb02204dc287911e711ca33f55eda17160c846ecbbe8379956f1a82f01984709c1d4"
        "0a0121025bfee5c1c3ea5df6e587821465ceed2f6cd233776c39ea98a793387c745b62c9ffff"
        "ffff0100e1f505000000001976a9140e2e16cdd3940acc48f784ee26779709dcd7227388ac00"
        "000000";
    if (strcmp(got, want) != 0) {
        fprintf(stderr, "FAIL signed tx mismatch\n  got  %s\n  want %s\n", got, want);
        return 1;
    }

    /* independently: the sighash our signature commits to must verify */
    uint8_t h[32];
    if (!kw_tx_sighash(&tx, 0, spk, sizeof spk, KW_SIGHASH_ALL, h)) { fprintf(stderr, "FAIL sighash\n"); return 1; }
    const uint8_t *ss = tx.vin[0].script;
    size_t derlen = ss[0] - 1;                 /* strip the trailing hashtype byte */
    if (!kw_ec_verify(pub, h, ss + 1, derlen)) { fprintf(stderr, "FAIL signature does not verify\n"); return 1; }

    /* P2SH 2-of-2: build the redeem script, co-sign an input with both keys,
       verify each partial signature, and assemble the redeeming scriptSig. */
    {
        uint8_t sk2[32]; memset(sk2, 0x02, 32);
        uint8_t pub2[33];
        if (!kw_ec_pubkey(sk2, pub2)) { fprintf(stderr, "FAIL: pub2\n"); return 1; }
        uint8_t keys[2][33];
        memcpy(keys[0], pub, 33); memcpy(keys[1], pub2, 33);

        uint8_t redeem[128];
        size_t rl = kw_script_multisig(2, keys, 2, redeem, sizeof redeem);
        if (rl == 0 || redeem[0] != 0x52 || redeem[rl - 2] != 0x52 || redeem[rl - 1] != 0xae) {
            fprintf(stderr, "FAIL: redeem script\n"); return 1;
        }
        uint8_t p2sh[23];
        if (kw_script_p2sh(redeem, rl, p2sh) != 23 || p2sh[0] != 0xa9 || p2sh[1] != 0x14 || p2sh[22] != 0x87) {
            fprintf(stderr, "FAIL: p2sh spk\n"); return 1;
        }

        kw_tx mtx; kw_tx_init(&mtx);
        kw_tx_add_input(&mtx, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", 0);
        uint8_t ospk[25] = { 0x76, 0xa9, 0x14 }; memset(ospk + 3, 0x11, 20); ospk[23] = 0x88; ospk[24] = 0xac;
        kw_tx_add_output(&mtx, 100000000ULL, ospk, 25);

        uint8_t mh[32];
        if (!kw_tx_sighash(&mtx, 0, redeem, rl, KW_SIGHASH_ALL, mh)) { fprintf(stderr, "FAIL: ms sighash\n"); return 1; }

        uint8_t sigA[73], sigB[73]; size_t la = sizeof sigA, lb = sizeof sigB;
        if (!kw_tx_signature(&mtx, 0, sk,  redeem, rl, KW_SIGHASH_ALL, sigA, &la) ||
            !kw_tx_signature(&mtx, 0, sk2, redeem, rl, KW_SIGHASH_ALL, sigB, &lb)) { fprintf(stderr, "FAIL: ms sign\n"); return 1; }
        if (!kw_ec_verify(pub, mh, sigA, la - 1) || !kw_ec_verify(pub2, mh, sigB, lb - 1)) {
            fprintf(stderr, "FAIL: ms sig verify\n"); return 1;
        }

        const uint8_t *sigs[2] = { sigA, sigB }; size_t lens[2] = { la, lb };
        if (!kw_tx_set_multisig(&mtx, 0, sigs, lens, 2, redeem, rl)) { fprintf(stderr, "FAIL: ms assemble\n"); return 1; }
        const uint8_t *ms = mtx.vin[0].script; size_t msl = mtx.vin[0].scriptlen;
        if (ms[0] != 0x00 || msl < rl + 1 || memcmp(ms + msl - rl, redeem, rl) != 0) {
            fprintf(stderr, "FAIL: ms scriptSig shape\n"); return 1;
        }
    }

    kw_ec_stop();
    printf("tx ok: p2pkh byte-for-byte vs libdogecoin, p2sh 2-of-2 co-sign verifies\n");
    return 0;
}
