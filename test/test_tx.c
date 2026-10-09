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

        /* the redeem script reads back into its parts */
        int pm = 0, pn = 0; uint8_t pk[16][33];
        if (!kw_script_multisig_parse(redeem, rl, &pm, pk, &pn) || pm != 2 || pn != 2 ||
            memcmp(pk[0], pub, 33) != 0 || memcmp(pk[1], pub2, 33) != 0) {
            fprintf(stderr, "FAIL: multisig parse\n"); return 1;
        }
        if (kw_script_multisig_parse(redeem, rl - 1, &pm, pk, &pn)) {
            fprintf(stderr, "FAIL: truncated multisig accepted\n"); return 1;
        }

        /* serialize -> parse -> serialize is byte-identical */
        uint8_t raw1[4096], raw2[4096];
        size_t n1 = kw_tx_serialize(&mtx, raw1, sizeof raw1);
        kw_tx ptx;
        if (!n1 || kw_tx_parse(raw1, n1, &ptx) != n1) { fprintf(stderr, "FAIL: tx parse\n"); return 1; }
        size_t n2 = kw_tx_serialize(&ptx, raw2, sizeof raw2);
        if (n2 != n1 || memcmp(raw1, raw2, n1) != 0) { fprintf(stderr, "FAIL: parse round-trip\n"); return 1; }
        if (kw_tx_parse(raw1, n1 - 1, &ptx)) { fprintf(stderr, "FAIL: truncated tx accepted\n"); return 1; }
    }

    /* the uncompressed p2pkh variant pushes the 65-byte key and still verifies */
    {
        kw_tx utx; kw_tx_init(&utx);
        kw_tx_add_input(&utx, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", 1);
        uint8_t uspk[25] = { 0x76, 0xa9, 0x14 }; memset(uspk + 3, 0x22, 20); uspk[23] = 0x88; uspk[24] = 0xac;
        kw_tx_add_output(&utx, 50000000ULL, uspk, 25);
        if (!kw_tx_sign_p2pkh_uncompressed(&utx, 0, sk, uspk, 25)) { fprintf(stderr, "FAIL: uncompressed sign\n"); return 1; }
        const uint8_t *us = utx.vin[0].script; size_t usl = utx.vin[0].scriptlen;
        size_t sl = us[0];
        if (usl != 2 + sl + 65 || us[1 + sl] != 65 || us[2 + sl] != 0x04) {
            fprintf(stderr, "FAIL: uncompressed scriptSig shape\n"); return 1;
        }
        uint8_t uh[32];
        if (!kw_tx_sighash(&utx, 0, uspk, 25, KW_SIGHASH_ALL, uh) ||
            !kw_ec_verify(pub, uh, us + 1, sl - 1)) {
            fprintf(stderr, "FAIL: uncompressed sig verify\n"); return 1;
        }
    }

    /* Consensus strips every OP_CODESEPARATOR from the scriptCode before hashing
       it. Signing the script as given produced a digest no node computes, and
       cosign --finish then verified against that same wrong digest, so its
       refuse-before-broadcast check passed for a signature the chain rejects. */
    {
        if (!kw_ec_start()) { fprintf(stderr, "FAIL: ec restart\n"); return 1; }
        uint8_t sk[32]; memset(sk, 0x11, 32);
        uint8_t pub[33];
        if (!kw_ec_pubkey(sk, pub)) { fprintf(stderr, "FAIL: codesep pubkey\n"); return 1; }
        uint8_t keys[2][33];
        memcpy(keys[0], pub, 33);
        memset(keys[1], 0, 33); keys[1][0] = 0x02; keys[1][1] = 0x07;
        uint8_t other[32]; memset(other, 0x22, 32);
        if (!kw_ec_pubkey(other, keys[1])) { fprintf(stderr, "FAIL: codesep pubkey 2\n"); return 1; }

        uint8_t redeem[128];
        size_t rl = kw_script_multisig(2, keys, 2, redeem, sizeof redeem);
        uint8_t withsep[200];
        withsep[0] = 0xab;                              /* OP_CODESEPARATOR */
        memcpy(withsep + 1, redeem, rl);

        kw_tx tx; kw_tx_init(&tx);
        kw_tx_add_input(&tx, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", 0);
        uint8_t h20[20]; memset(h20, 0x33, 20);
        kw_tx_add_output_p2pkh(&tx, 100000000ULL, h20);

        /* 0xab inside a push is data, not OP_CODESEPARATOR: one hash160 in
           thirteen contains that byte, and dropping it hands the signer a
           scriptCode no node computes, which is a signature that fails with
           NULLFAIL on the way in. */
        {
            uint8_t h20ab[20];
            memset(h20ab, 0x11, 20);
            h20ab[7] = 0xab;
            uint8_t p2pkh[25] = { 0x76, 0xa9, 0x14 };
            memcpy(p2pkh + 3, h20ab, 20);
            p2pkh[23] = 0x88; p2pkh[24] = 0xac;

            /* the same script with that one byte deleted, which is what a
               stripper working on bytes rather than opcodes turns it into */
            uint8_t eaten[24];
            memcpy(eaten, p2pkh, 3 + 7);
            memcpy(eaten + 3 + 7, p2pkh + 3 + 8, 25 - (3 + 8));

            uint8_t with[32], without[32];
            if (!kw_tx_sighash(&tx, 0, p2pkh, 25, KW_SIGHASH_ALL, with) ||
                !kw_tx_sighash(&tx, 0, eaten, 24, KW_SIGHASH_ALL, without)) {
                fprintf(stderr, "FAIL: p2pkh codesep sighash\n"); return 1;
            }
            if (memcmp(with, without, 32) == 0) {
                fprintf(stderr, "FAIL: 0xab inside a hash160 was dropped as an opcode\n");
                return 1;
            }
            uint8_t sigab[KW_EC_SIG_DER_MAX + 1]; size_t sabl = sizeof sigab;
            if (!kw_tx_signature(&tx, 0, sk, p2pkh, 25, KW_SIGHASH_ALL, sigab, &sabl) ||
                !kw_ec_verify(pub, with, sigab, sabl - 1)) {
                fprintf(stderr, "FAIL: a script with 0xab in its data did not sign cleanly\n");
                return 1;
            }
        }

        uint8_t hsep[32], hstripped[32];
        if (!kw_tx_sighash(&tx, 0, withsep, rl + 1, KW_SIGHASH_ALL, hsep) ||
            !kw_tx_sighash(&tx, 0, redeem, rl, KW_SIGHASH_ALL, hstripped)) {
            fprintf(stderr, "FAIL: codesep sighash\n"); return 1;
        }
        if (memcmp(hsep, hstripped, 32) != 0) {
            fprintf(stderr, "FAIL: a separator in the scriptCode changed the digest\n"); return 1;
        }

        uint8_t sig[KW_EC_SIG_DER_MAX + 1]; size_t siglen = sizeof sig;
        if (!kw_tx_signature(&tx, 0, sk, withsep, rl + 1, KW_SIGHASH_ALL, sig, &siglen)) {
            fprintf(stderr, "FAIL: codesep sign\n"); return 1;
        }
        if (!kw_ec_verify(pub, hstripped, sig, siglen - 1)) {
            fprintf(stderr, "FAIL: the signature does not verify against the digest a node computes\n");
            return 1;
        }

        /* A separator that runs before the CHECKSIG moves where the scriptCode
           starts: consensus hashes from just past the last one executed. Removing
           every separator but keeping the whole script signed five opcodes where
           the node hashes two, and the spend came back "mandatory-script-verify-
           flag-failed (Signature must be zero for failed CHECK(MULTI)SIG)". */
        {
            uint8_t before[64], after[64];
            size_t bn = 0, an = 0;
            before[bn++] = 0x51;                    /* OP_1   */
            before[bn++] = 0x75;                    /* OP_DROP */
            before[bn++] = 0xab;                    /* OP_CODESEPARATOR */
            before[bn++] = 0x21;
            memcpy(before + bn, pub, 33); bn += 33;
            before[bn++] = 0xac;                    /* OP_CHECKSIG */

            after[an++] = 0x21;                     /* what a node hashes: the tail */
            memcpy(after + an, pub, 33); an += 33;
            after[an++] = 0xac;

            uint8_t hb[32], ha[32];
            if (!kw_tx_sighash(&tx, 0, before, bn, KW_SIGHASH_ALL, hb) ||
                !kw_tx_sighash(&tx, 0, after, an, KW_SIGHASH_ALL, ha)) {
                fprintf(stderr, "FAIL: executed-separator sighash\n"); return 1;
            }
            if (memcmp(hb, ha, 32) != 0) {
                fprintf(stderr, "FAIL: the scriptCode did not start at the executed "
                                "separator\n"); return 1;
            }

            /* A separator after the checksig moves nothing: consensus hashes
               from the last one executed before the checksig being satisfied,
               and taking the last one anywhere signed OP_1 alone here, which
               the node refused as mandatory-script-verify-flag-failed. */
            {
                uint8_t after[80], want[80];
                size_t an2 = 0, wn = 0;
                after[an2++] = 0x21;
                memcpy(after + an2, pub, 33); an2 += 33;
                after[an2++] = 0xad;                /* OP_CHECKSIGVERIFY */
                after[an2++] = 0xab;                /* OP_CODESEPARATOR, after it */
                after[an2++] = 0x51;                /* OP_1 */

                want[wn++] = 0x21;                  /* what a node hashes: the lot, */
                memcpy(want + wn, pub, 33); wn += 33;
                want[wn++] = 0xad;                  /* with the separator removed */
                want[wn++] = 0x51;

                uint8_t h1[32], h2[32];
                if (!kw_tx_sighash(&tx, 0, after, an2, KW_SIGHASH_ALL, h1) ||
                    !kw_tx_sighash(&tx, 0, want, wn, KW_SIGHASH_ALL, h2)) {
                    fprintf(stderr, "FAIL: trailing-separator sighash\n"); return 1;
                }
                if (memcmp(h1, h2, 32) != 0) {
                    fprintf(stderr, "FAIL: a separator after the checksig moved the "
                                    "scriptCode\n"); return 1;
                }

                /* and one on each side of it: the leading one still decides */
                uint8_t both[80];
                size_t bn2 = 0;
                both[bn2++] = 0xab;
                memcpy(both + bn2, after, an2); bn2 += an2;
                uint8_t h3[32];
                if (!kw_tx_sighash(&tx, 0, both, bn2, KW_SIGHASH_ALL, h3)) {
                    fprintf(stderr, "FAIL: leading and trailing separator sighash\n"); return 1;
                }
                if (memcmp(h3, h2, 32) != 0) {
                    fprintf(stderr, "FAIL: a leading separator and a trailing one did "
                                    "not give the node's digest\n"); return 1;
                }

                /* two checksigs with a separator between them: which one this
                   signature is for decides the digest, and the bytes do not say */
                uint8_t two[160];
                size_t tn = 0;
                two[tn++] = 0x21; memcpy(two + tn, pub, 33); tn += 33; two[tn++] = 0xad;
                two[tn++] = 0xab;
                two[tn++] = 0x21; memcpy(two + tn, pub, 33); tn += 33; two[tn++] = 0xac;
                uint8_t h4[32];
                if (kw_tx_sighash(&tx, 0, two, tn, KW_SIGHASH_ALL, h4)) {
                    fprintf(stderr, "FAIL: signed a script whose separator sits between "
                                    "two checksigs\n"); return 1;
                }
            }

            /* and with a branch in the script, which separator runs is not in the
               bytes: a signer that cannot know must refuse rather than guess. */
            uint8_t branch[80];
            size_t cn = 0;
            branch[cn++] = 0x63;                    /* OP_IF */
            branch[cn++] = 0xab;                    /* OP_CODESEPARATOR */
            branch[cn++] = 0x68;                    /* OP_ENDIF */
            branch[cn++] = 0x21;
            memcpy(branch + cn, pub, 33); cn += 33;
            branch[cn++] = 0xac;
            uint8_t hc[32];
            if (kw_tx_sighash(&tx, 0, branch, cn, KW_SIGHASH_ALL, hc)) {
                fprintf(stderr, "FAIL: signed a script whose separator may or may not "
                                "run\n"); return 1;
            }
        }
    }

    kw_ec_stop();
    printf("tx ok: p2pkh byte-for-byte vs libdogecoin, p2sh 2-of-2 co-sign verifies, parse round-trips,\n"
           "  uncompressed p2pkh verifies, a scriptCode starts at the separator executed\n  before its checksig and not at one after it, and a script a signer cannot\n  resolve is refused rather than guessed\n");
    return 0;
}
