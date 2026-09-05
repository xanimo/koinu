/* dogewallet - transaction signing test
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
    if (!dw_ec_start()) { fprintf(stderr, "FAIL ec_start\n"); return 1; }

    /* the mainnet key whose address anchors test_address */
    uint8_t sk[32], pub[33], h160[20];
    int comp; uint8_t ver;
    if (!dw_wif_decode("QPbCXTPCJU3NRPLGbVYjXRYw1WcFFQ6apxiUNRP4bSDQCojDfLpv", sk, &comp, &ver)) {
        fprintf(stderr, "FAIL wif\n"); return 1;
    }
    dw_ec_pubkey(sk, pub);
    dw_hash160(pub, 33, h160);
    char h160hex[41]; dw_hex_encode(h160, 20, h160hex, sizeof h160hex);
    if (strcmp(h160hex, "0e2e16cdd3940acc48f784ee26779709dcd72273") != 0) {
        fprintf(stderr, "FAIL hash160 %s\n", h160hex); return 1;
    }

    uint8_t spk[25];
    spk[0]=0x76; spk[1]=0xa9; spk[2]=0x14; memcpy(spk+3, h160, 20); spk[23]=0x88; spk[24]=0xac;

    dw_tx tx;
    dw_tx_init(&tx);
    if (!dw_tx_add_input(&tx, "0000000000000000000000000000000000000000000000000000000000000001", 0)) {
        fprintf(stderr, "FAIL add_input\n"); return 1;
    }
    if (!dw_tx_add_output_p2pkh(&tx, 100000000ULL, h160)) { fprintf(stderr, "FAIL add_output\n"); return 1; }
    if (!dw_tx_sign_p2pkh(&tx, 0, sk, spk, sizeof spk)) { fprintf(stderr, "FAIL sign\n"); return 1; }

    uint8_t raw[1024];
    size_t n = dw_tx_serialize(&tx, raw, sizeof raw);
    if (!n) { fprintf(stderr, "FAIL serialize\n"); return 1; }
    char got[2048]; dw_hex_encode(raw, n, got, sizeof got);

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
    if (!dw_tx_sighash(&tx, 0, spk, sizeof spk, DW_SIGHASH_ALL, h)) { fprintf(stderr, "FAIL sighash\n"); return 1; }
    const uint8_t *ss = tx.vin[0].script;
    size_t derlen = ss[0] - 1;                 /* strip the trailing hashtype byte */
    if (!dw_ec_verify(pub, h, ss + 1, derlen)) { fprintf(stderr, "FAIL signature does not verify\n"); return 1; }

    dw_ec_stop();
    printf("tx ok: p2pkh spend matches libdogecoin byte-for-byte, signature verifies\n");
    return 0;
}
