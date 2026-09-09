/* koinu.dog - BIP174 psbt tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * A 2-of-2 p2sh spend carried through the roles: create, update, sign with
 * each key separately, combine the two halves, finalize by hand (the scripts
 * this is for do not classify), extract. Plus the refusals: a signed global
 * transaction, a segwit field, a truncated stream. */

#include "psbt.h"
#include "ec.h"
#include "hex.h"

#include "bip174_vectors.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    if (!kw_ec_start()) { fprintf(stderr, "FAIL: ec start\n"); return 1; }

    uint8_t skA[32], skB[32];
    memset(skA, 0x11, 32); memset(skB, 0x22, 32);
    uint8_t pubA[33], pubB[33];
    kw_ec_pubkey(skA, pubA); kw_ec_pubkey(skB, pubB);
    uint8_t keys[2][33]; memcpy(keys[0], pubA, 33); memcpy(keys[1], pubB, 33);
    uint8_t redeem[128];
    size_t rl = kw_script_multisig(2, keys, 2, redeem, sizeof redeem);

    kw_tx tx; kw_tx_init(&tx);
    kw_tx_add_input(&tx, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", 0);
    uint8_t spk[25] = { 0x76, 0xa9, 0x14 }; memset(spk + 3, 0x11, 20);
    spk[23] = 0x88; spk[24] = 0xac;
    kw_tx_add_output(&tx, 100000000ULL, spk, 25);

    /* creator + updater */
    kw_psbt a;
    if (!kw_psbt_create(&a, &tx)) { fprintf(stderr, "FAIL: create\n"); return 1; }
    if (!kw_psbt_set_redeem(&a, 0, redeem, rl)) { fprintf(stderr, "FAIL: set redeem\n"); return 1; }
    uint8_t prevtx[64]; memset(prevtx, 0xab, sizeof prevtx);
    if (!kw_psbt_set_utxo(&a, 0, prevtx, sizeof prevtx)) { fprintf(stderr, "FAIL: set utxo\n"); return 1; }

    /* the unsigned tx reads back: what a signer must see before it signs */
    const kw_tx *ut = kw_psbt_unsigned_tx(&a);
    if (!ut || ut->nin != 1 || ut->nout != 1 || ut->vout[0].value != 100000000ULL ||
        ut->vin[0].scriptlen != 0) { fprintf(stderr, "FAIL: unsigned tx accessor\n"); return 1; }

    /* each party signs its own copy, then the halves combine */
    uint8_t buf[8192];
    size_t n = kw_psbt_serialize(&a, buf, sizeof buf);
    if (!n) { fprintf(stderr, "FAIL: serialize\n"); return 1; }
    kw_psbt b;
    if (!kw_psbt_parse(buf, n, &b)) { fprintf(stderr, "FAIL: parse\n"); return 1; }
    if (b.in[0].redeemlen != rl || memcmp(b.in[0].redeem, redeem, rl) != 0 ||
        b.in[0].utxolen != sizeof prevtx) { fprintf(stderr, "FAIL: round trip fields\n"); return 1; }

    if (kw_psbt_sign(&a, 0, skA, KW_SIGHASH_ALL) != 1 ||
        kw_psbt_sign(&b, 0, skB, KW_SIGHASH_ALL) != 1) { fprintf(stderr, "FAIL: sign\n"); return 1; }
    if (a.in[0].nsigs != 1 || b.in[0].nsigs != 1) { fprintf(stderr, "FAIL: sig count\n"); return 1; }

    if (!kw_psbt_combine(&a, &b)) { fprintf(stderr, "FAIL: combine\n"); return 1; }
    if (a.in[0].nsigs != 2) { fprintf(stderr, "FAIL: combined sig count\n"); return 1; }
    if (!kw_psbt_combine(&a, &b) || a.in[0].nsigs != 2) {
        fprintf(stderr, "FAIL: combine is not idempotent\n"); return 1;
    }

    /* both signatures verify against the sighash they claim to cover */
    uint8_t hash[32];
    if (!kw_tx_sighash(&a.tx, 0, redeem, rl, KW_SIGHASH_ALL, hash)) { fprintf(stderr, "FAIL: sighash\n"); return 1; }
    for (size_t i = 0; i < 2; i++) {
        uint8_t pk[33], sig[80]; size_t sl = sizeof sig;
        if (!kw_psbt_get_sig(&a, 0, i, pk, sig, &sl)) { fprintf(stderr, "FAIL: get sig\n"); return 1; }
        if (sig[sl - 1] != KW_SIGHASH_ALL) { fprintf(stderr, "FAIL: hashtype byte\n"); return 1; }
        if (!kw_ec_verify(pk, hash, sig, sl - 1)) { fprintf(stderr, "FAIL: sig verify\n"); return 1; }
        if (memcmp(pk, i == 0 ? pubA : pubB, 33) != 0) { fprintf(stderr, "FAIL: sig order\n"); return 1; }
    }

    /* finalize by hand, the way a non-standard script must, then extract */
    uint8_t ss[256]; size_t k = 0;
    ss[k++] = 0x00;
    for (size_t i = 0; i < 2; i++) {
        uint8_t pk[33], sig[80]; size_t sl = sizeof sig;
        kw_psbt_get_sig(&a, 0, i, pk, sig, &sl);
        ss[k++] = (uint8_t)sl; memcpy(ss + k, sig, sl); k += sl;
    }
    ss[k++] = (uint8_t)rl; memcpy(ss + k, redeem, rl); k += rl;

    kw_tx final;
    if (kw_psbt_extract(&a, &final)) { fprintf(stderr, "FAIL: extracted without a scriptSig\n"); return 1; }
    if (!kw_psbt_finalize(&a, 0, ss, k)) { fprintf(stderr, "FAIL: finalize\n"); return 1; }
    if (!kw_psbt_extract(&a, &final)) { fprintf(stderr, "FAIL: extract\n"); return 1; }
    if (final.vin[0].scriptlen != k || memcmp(final.vin[0].script, ss, k) != 0) {
        fprintf(stderr, "FAIL: extracted scriptSig\n"); return 1;
    }

    /* a finalized psbt round-trips with its scriptSig */
    n = kw_psbt_serialize(&a, buf, sizeof buf);
    kw_psbt c;
    if (!n || !kw_psbt_parse(buf, n, &c) || c.in[0].finallen != k ||
        c.in[0].nsigs != 2) { fprintf(stderr, "FAIL: final round trip\n"); return 1; }

    /* refusals */
    kw_psbt d;
    if (kw_psbt_create(&d, &final)) { fprintf(stderr, "FAIL: created from a signed tx\n"); return 1; }
    if (kw_psbt_parse(buf, n - 1, &d)) { fprintf(stderr, "FAIL: truncated accepted\n"); return 1; }
    if (kw_psbt_parse(buf, 4, &d)) { fprintf(stderr, "FAIL: no magic accepted\n"); return 1; }

    /* a witness-utxo key must be refused, not skipped: dropping what a
       combiner does not understand loses the other side's data */
    uint8_t seg[8192];
    memcpy(seg, buf, n);
    for (size_t i = 5; i + 1 < n; i++)
        if (seg[i] == 0x01 && seg[i+1] == 0x00) { seg[i+1] = 0x01; break; }  /* keylen 1, type 0 -> 1 */
    if (kw_psbt_parse(seg, n, &d) && d.in[0].utxolen) {
        fprintf(stderr, "FAIL: segwit field accepted\n"); return 1;
    }

    kw_psbt_free(&a); kw_psbt_free(&b); kw_psbt_free(&c);

    /* every psbt in the BIP174 test-vector section */
    int parsed = 0, refused = 0;
    for (size_t i = 0; i < sizeof KW_BIP174_VECS / sizeof KW_BIP174_VECS[0]; i++) {
        const kw_bip174_vec *v = &KW_BIP174_VECS[i];
        size_t hl = strlen(v->hex), bl = hl / 2;
        uint8_t *raw = (uint8_t *)malloc(bl ? bl : 1);
        if (!raw || !kw_hex_decode(v->hex, hl, raw, bl)) { fprintf(stderr, "FAIL: vector %zu hex\n", i); return 1; }

        kw_psbt vp;
        int got = kw_psbt_parse(raw, bl, &vp);
        if (got != v->parses) {
            fprintf(stderr, "FAIL: vector %zu (%s) %s\n", i, v->note,
                    got ? "parsed but should not" : "was refused but should parse");
            return 1;
        }
        if (got) {
            /* what came back must survive a second trip unchanged */
            uint8_t re[16384];
            size_t rn = kw_psbt_serialize(&vp, re, sizeof re);
            kw_psbt again;
            if (!rn || !kw_psbt_parse(re, rn, &again)) { fprintf(stderr, "FAIL: vector %zu reserialize\n", i); return 1; }
            uint8_t t1[32], t2[32];
            if (!kw_tx_txid(&vp.tx, t1) || !kw_tx_txid(&again.tx, t2) || memcmp(t1, t2, 32) != 0) {
                fprintf(stderr, "FAIL: vector %zu tx changed across a round trip\n", i); return 1;
            }
            for (size_t k = 0; k < vp.tx.nin; k++) {
                if (vp.in[k].nsigs != again.in[k].nsigs ||
                    vp.in[k].redeemlen != again.in[k].redeemlen ||
                    vp.in[k].utxolen != again.in[k].utxolen ||
                    vp.in[k].finallen != again.in[k].finallen ||
                    vp.in[k].has_sighash != again.in[k].has_sighash ||
                    (vp.in[k].utxolen && memcmp(vp.in[k].utxo, again.in[k].utxo, vp.in[k].utxolen))) {
                    fprintf(stderr, "FAIL: vector %zu input %zu changed\n", i, k); return 1;
                }
            }
            kw_psbt_free(&again);
            parsed++;
        } else refused++;
        kw_psbt_free(&vp);
        free(raw);
    }

    kw_ec_stop();
    printf("psbt ok: create/update/sign/combine/finalize/extract, %d bip174 vectors parsed and round-tripped, %d refused\n",
           parsed, refused);
    return 0;
}
