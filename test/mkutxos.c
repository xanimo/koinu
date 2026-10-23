/* koinu.dog - build a utxo set file for the shell tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * A utxo set names an amount, and since v2 that amount has to be the one the
 * transaction creating it carries, so a test cannot write the file by hand any
 * more. This builds a funding transaction per entry and runs it through the
 * same apply path a scan uses, which is what produces the binding.
 *
 *   mkutxos PATH SPKHEX VALUE HEIGHT [SPKHEX VALUE HEIGHT ...]
 */

#include "hex.h"
#include "tx.h"
#include "utxo.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    kw_watchset *ws;
    kw_utxoset *us;
    int i, n;

    if (argc < 5 || (argc - 2) % 3) {
        fprintf(stderr, "usage: mkutxos PATH SPKHEX VALUE HEIGHT [...]\n");
        return 2;
    }
    n = (argc - 2) / 3;

    if (!(ws = kw_watchset_new()) || !(us = kw_utxoset_new())) {
        fprintf(stderr, "mkutxos: init\n");
        return 1;
    }

    for (i = 0; i < n; i++) {
        const char *spkhex = argv[2 + 3 * i];
        unsigned long long value = strtoull(argv[3 + 3 * i], NULL, 10);
        unsigned height = (unsigned)strtoul(argv[4 + 3 * i], NULL, 10);
        uint8_t spk[KW_SPK_MAX], raw[4096];
        size_t spklen = strlen(spkhex) / 2, rawlen;
        char prev[65];
        kw_tx *tx;
        int k;

        if (spklen == 0 || spklen > KW_SPK_MAX || strlen(spkhex) % 2 ||
            !kw_hex_decode(spkhex, strlen(spkhex), spk, spklen)) {
            fprintf(stderr, "mkutxos: bad script %s\n", spkhex);
            return 1;
        }
        if (!kw_watchset_add(ws, spk, spklen)) { fprintf(stderr, "mkutxos: watch\n"); return 1; }

        /* A distinct prevout per entry, so each funding transaction has its own
           txid and the set holds separate outpoints. */
        for (k = 0; k < 64; k++) prev[k] = '0';
        prev[64] = '\0';
        snprintf(prev + 60, 5, "%04x", (unsigned)(i + 1) & 0xffffu);

        tx = kw_tx_new();
        if (!tx) { fprintf(stderr, "mkutxos: out of memory\n"); return 1; }
        if (!kw_tx_add_input(tx, prev, 0) ||
            !kw_tx_add_output(tx, value, spk, spklen)) {
            fprintf(stderr, "mkutxos: build\n");
            return 1;
        }
        rawlen = kw_tx_serialize(tx, raw, sizeof raw);
        kw_tx_free(tx);
        if (!rawlen) { fprintf(stderr, "mkutxos: serialize\n"); return 1; }

        if (!kw_utxoset_apply_tx(us, ws, raw, rawlen, height)) {
            fprintf(stderr, "mkutxos: apply\n");
            return 1;
        }
    }

    if (kw_utxoset_count(us) != (size_t)n) {
        fprintf(stderr, "mkutxos: built %zu of %d entries\n", kw_utxoset_count(us), n);
        return 1;
    }
    if (!kw_utxoset_save(us, argv[1])) { fprintf(stderr, "mkutxos: save\n"); return 1; }

    kw_utxoset_free(us);
    kw_watchset_free(ws);
    return 0;
}
