/* koinu.dog - the sighash against signatures the network already accepted
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Every vector is a real mainnet spend: a prevout scriptPubKey read off the chain, an
 * input index, and the transaction that spent it. Each signature in it was made years
 * ago by other software and accepted by the network, so it verifies only against the
 * digest consensus actually uses. This tree computes that digest independently and
 * checks the signatures against it, which is why a wrong sighash cannot pass: there
 * is no shared code between the thing being tested and the thing testing it.
 *
 * Every signature in a vector must verify, not one of them. A 2-of-2 carries two, and
 * "one verified" would pass on half a digest.
 *
 * test/mkvectors_chain.c writes the file, off a peer, and deliberately computes no
 * digest of its own: a generator that verified before emitting could only produce
 * vectors this tree already passes. */

#include "ec.h"
#include "hex.h"
#include "tx.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VECTORS "test/vectors/sighash_mainnet.txt"

/* the data pushes of a scriptSig, as in the generator */
static int pushes(const uint8_t *s, size_t len, const uint8_t **at, size_t *sz, int max, int *n)
{
    size_t o = 0;
    *n = 0;
    while (o < len) {
        uint8_t op = s[o++];
        size_t l;
        if (op == 0) l = 0;
        else if (op <= 75) l = op;
        else if (op == 0x4c) { if (o >= len) return 0; l = s[o++]; }
        else if (op == 0x4d) { if (o + 1 >= len) return 0; l = (size_t)s[o] | ((size_t)s[o+1] << 8); o += 2; }
        else return 0;
        if (o + l > len || *n >= max) return 0;
        at[*n] = s + o;
        sz[*n] = l;
        (*n)++;
        o += l;
    }
    return 1;
}

int main(void)
{
    FILE *f = fopen(VECTORS, "r");
    if (!f) { fprintf(stderr, "FAIL: cannot open %s\n", VECTORS); return 1; }
    if (!kw_ec_start()) { fprintf(stderr, "FAIL: ec init\n"); fclose(f); return 1; }

    char *line = NULL;
    size_t cap = 0;
    long checked = 0, sigs = 0, np2pkh = 0, np2sh = 0, multi[17][17];
    memset(multi, 0, sizeof multi);
    int rc = 0;

    while (getline(&line, &cap, f) > 0) {
        if (line[0] == '#' || line[0] == '\n') continue;

        char spkhex[512], txhex[65536];
        unsigned long index;
        if (sscanf(line, "%511s %lu %65535s", spkhex, &index, txhex) != 3) {
            fprintf(stderr, "FAIL: malformed vector\n"); rc = 1; break;
        }

        uint8_t spk[256];
        size_t spklen = strlen(spkhex) / 2;
        static uint8_t raw[32768];
        size_t rawlen = strlen(txhex) / 2;
        if (spklen > sizeof spk || rawlen > sizeof raw ||
            !kw_hex_decode(spkhex, strlen(spkhex), spk, spklen) ||
            !kw_hex_decode(txhex, strlen(txhex), raw, rawlen)) {
            fprintf(stderr, "FAIL: vector does not decode\n"); rc = 1; break;
        }

        kw_tx tx;
        if (kw_tx_parse(raw, rawlen, &tx) != rawlen) {
            fprintf(stderr, "FAIL: vector transaction does not parse\n"); rc = 1; break;
        }
        if (index >= tx.nin) { fprintf(stderr, "FAIL: input %lu is past the end\n", index); rc = 1; break; }

        /* what the digest covers, and which pushes are signatures: for P2PKH the
           scriptPubKey and one signature, for P2SH the redeem script and one per
           signature the multisig needs */
        const uint8_t *at[8];
        size_t sz[8];
        int n = 0;
        if (!pushes(tx.vin[index].script, tx.vin[index].scriptlen, at, sz, 8, &n)) {
            fprintf(stderr, "FAIL: scriptSig does not read as pushes\n"); rc = 1; break;
        }

        const uint8_t *code;
        size_t codelen;
        int first, count, is_p2sh;
        uint8_t keys[16][33];
        int m = 0, k = 0;

        if (spklen == 25 && spk[0] == 0x76) {
            code = spk; codelen = spklen;
            first = 0; count = 1; is_p2sh = 0;
            if (n != 2) { fprintf(stderr, "FAIL: p2pkh scriptSig has %d pushes\n", n); rc = 1; break; }
            np2pkh++;
        } else if (spklen == 23 && spk[0] == 0xa9) {
            code = at[n - 1]; codelen = sz[n - 1];
            if (!kw_script_multisig_parse(code, codelen, &m, keys, &k)) {
                fprintf(stderr, "FAIL: redeem script is not multisig\n"); rc = 1; break;
            }
            first = 1; count = n - 2; is_p2sh = 1;
            if (count != m) { fprintf(stderr, "FAIL: %d signatures for a %d-of-%d\n", count, m, k); rc = 1; break; }
            if (m <= 16 && k <= 16) multi[m][k]++;
            np2sh++;
        } else {
            fprintf(stderr, "FAIL: vector is neither p2pkh nor p2sh\n"); rc = 1; break;
        }

        /* every signature, against the pubkeys in order, as CHECKMULTISIG does */
        int key_at = 0;
        for (int q = 0; q < count; q++) {
            const uint8_t *sig = at[first + q];
            size_t siglen = sz[first + q];
            if (siglen < 2) { fprintf(stderr, "FAIL: empty signature\n"); rc = 1; break; }

            uint8_t digest[32];
            uint32_t hashtype = sig[siglen - 1];
            if (!kw_tx_sighash(&tx, index, code, codelen, hashtype, digest)) {
                fprintf(stderr, "FAIL: sighash refused for input %lu\n", index); rc = 1; break;
            }

            int ok = 0;
            if (!is_p2sh) {
                /* the pubkey pushed after the signature, in whatever form it was
                   written: mainnet is full of uncompressed keys and parse takes both */
                uint8_t pub[33];
                if (!kw_ec_pubkey_parse(at[1], sz[1], pub)) {
                    fprintf(stderr, "FAIL: input %lu pushes something that is not a pubkey\n", index);
                    rc = 1;
                    break;
                }
                ok = kw_ec_verify(pub, digest, sig, siglen - 1);
            } else {
                while (key_at < k && !ok) {
                    ok = kw_ec_verify(keys[key_at], digest, sig, siglen - 1);
                    key_at++;                     /* signatures and keys are both in order */
                }
            }
            if (!ok) {
                char id[65];
                uint8_t t[32], d[32];
                kw_tx_txid(&tx, t);
                for (int b = 0; b < 32; b++) d[b] = t[31 - b];
                kw_hex_encode(d, 32, id, sizeof id);
                fprintf(stderr, "FAIL: signature %d of input %lu in %s does not verify "
                                "against the digest this tree computes\n", q, index, id);
                rc = 1;
                break;
            }
            sigs++;
        }
        if (rc) break;
        checked++;
    }

    free(line);
    fclose(f);
    kw_ec_stop();
    if (rc) return 1;
    if (checked < 300) { fprintf(stderr, "FAIL: only %ld vectors, the file is short\n", checked); return 1; }

    printf("sighash ok: %ld mainnet spends, %ld signatures, %ld p2pkh and %ld p2sh",
           checked, sigs, np2pkh, np2sh);
    for (int a = 1; a <= 16; a++)
        for (int b = 1; b <= 16; b++)
            if (multi[a][b]) printf(", %ld %d-of-%d", multi[a][b], a, b);
    printf("\n");
    return 0;
}
