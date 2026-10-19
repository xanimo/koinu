/* koinu.dog - a signer linked against the signing half alone
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Not a test of signing, which test_tx and the libdogecoin vectors cover. This
 * exists to be linked: it uses the seed, the derivation, the keystore, the
 * share formats, the transaction builder and the psbt code, and nothing else,
 * so it links against libkoinu-sign.a with no net objects present. If someone
 * adds a dependency from crypto/ or wallet/ onto net/, this stops linking,
 * which is the point of it. */

#include "bip32.h"
#include "bip39.h"
#include "codex32.h"
#include "ec.h"
#include "keystore.h"
#include "psbt.h"
#include "slip39.h"
#include "tx.h"
#include "utxo.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    const kw_bip32_version ver = { 0x02facafd, 0x02facafe };   /* dogecoin */
    const char *mnemonic =
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon about";
    uint8_t seed[64], spk[25] = { 0x76, 0xa9, 0x14 };
    kw_bip32_key master, child;
    kw_slip39_group g = { 2, 3 };
    char shares[3][KW_SLIP39_MNEMONIC_MAX];
    char cx[KW_CODEX32_MAX_LEN * 3];
    size_t nshares = 0, ncx = 0, n;
    kw_tx tx;
    kw_psbt p;

    if (!kw_ec_start()) { fprintf(stderr, "signonly: no curve\n"); return 1; }
    if (!kw_bip39_to_seed(mnemonic, "", seed)) { fprintf(stderr, "signonly: seed\n"); return 1; }
    if (!kw_bip32_from_seed(seed, sizeof seed, ver, &master) ||
        !kw_bip32_ckd_priv(&master, 0, &child)) {
        fprintf(stderr, "signonly: derive\n");
        return 1;
    }

    memset(spk + 3, 0x42, 20);
    spk[23] = 0x88;
    spk[24] = 0xac;

    kw_tx_init(&tx);
    if (!kw_tx_add_input(&tx,
            "1111111111111111111111111111111111111111111111111111111111111111", 0) ||
        !kw_tx_add_output(&tx, 1000000, spk, sizeof spk)) {
        fprintf(stderr, "signonly: build\n");
        return 1;
    }
    /* the psbt first: it wraps an unsigned transaction */
    if (!kw_psbt_create(&p, &tx)) { fprintf(stderr, "signonly: psbt\n"); return 1; }
    kw_psbt_free(&p);
    if (!kw_tx_sign_p2pkh(&tx, 0, child.key + 1, spk, sizeof spk)) {
        fprintf(stderr, "signonly: sign\n");
        return 1;
    }

    if (kw_slip39_split(seed, sizeof seed, "", 0, 1, &g, 1,
                        &shares[0][0], KW_SLIP39_MNEMONIC_MAX, &nshares) != KW_SLIP39_OK ||
        nshares != 3) {
        fprintf(stderr, "signonly: slip39\n");
        return 1;
    }
    if (kw_codex32_split(seed, sizeof seed, "kw00", 2, 3,
                         cx, KW_CODEX32_MAX_LEN, &ncx) != KW_CODEX32_OK || ncx != 3) {
        fprintf(stderr, "signonly: codex32\n");
        return 1;
    }

    {
        uint8_t raw[4096];
        kw_watchset ws;
        kw_utxoset us;

        n = kw_tx_serialize(&tx, raw, sizeof raw);
        if (!n) { fprintf(stderr, "signonly: serialize\n"); return 1; }
        if (!kw_watchset_init(&ws) || !kw_utxoset_init(&us) ||
            !kw_watchset_add(&ws, spk, sizeof spk) ||
            !kw_utxoset_apply_tx(&us, &ws, raw, n, 1) ||
            kw_utxoset_count(&us) != 1) {
            fprintf(stderr, "signonly: utxo\n");
            return 1;
        }
        kw_utxoset_free(&us);
        kw_watchset_free(&ws);
    }

    kw_ec_stop();
    printf("signonly ok: %zu-byte spend signed, 3 slip39 and 3 codex32 shares, "
           "no net objects linked\n", n);
    return 0;
}
