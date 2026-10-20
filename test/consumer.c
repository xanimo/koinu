/* koinu.dog - a consumer of the installed tree
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Compiled by test/test_install.sh against an installed prefix and nothing
 * else: no -I into the source tree, so a public header that quietly includes a
 * private one is a compile error here rather than a surprise for whoever
 * packages this. One include, the way a consumer would write it. */

#include <koinu/koinu-sign.h>

#include <stdio.h>
#include <string.h>

int main(void)
{
    const char *mnemonic =
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon about";
    uint8_t seed[64], sealed[8192], back[64], spk[25] = { 0x76, 0xa9, 0x14 };
    kw_bip32_key master, child;
    kw_slip39_group g = { 2, 3 };
    char shares[3][KW_SLIP39_MNEMONIC_MAX], cx[3 * KW_CODEX32_MAX_LEN], addr[64];
    size_t n = 0, blen = 0, ns = 0, nc = 0, raw_n;
    kw_tx tx;
    uint8_t raw[4096], pub[33];

    if (!kw_ec_start()) { fprintf(stderr, "consumer: no curve\n"); return 1; }

    if (!kw_bip39_check(mnemonic) || !kw_bip39_to_seed(mnemonic, "", seed)) {
        fprintf(stderr, "consumer: bip39\n"); return 1;
    }
    n = kw_keystore_seal(seed, sizeof seed, "pw", &KW_KEYSTORE_DEFAULT,
                         sealed, sizeof sealed);
    if (!n || !kw_keystore_open(sealed, n, "pw", back, sizeof back, &blen) ||
        blen != sizeof seed || memcmp(back, seed, blen) != 0) {
        fprintf(stderr, "consumer: keystore\n"); return 1;
    }
    if (!kw_bip32_from_seed(seed, sizeof seed, KW_DOGE_MAINNET.bip32, &master) ||
        !kw_bip44_derive(&master, KW_DOGE_MAINNET.bip44_coin, 0, 0, 0, &child) ||
        !kw_bip32_pubkey(&child, pub) ||
        !kw_address_p2pkh(pub, KW_DOGE_MAINNET.p2pkh, addr, sizeof addr)) {
        fprintf(stderr, "consumer: derive\n"); return 1;
    }

    memset(spk + 3, 0x42, 20);
    spk[23] = 0x88;
    spk[24] = 0xac;
    kw_tx_init(&tx);
    if (!kw_tx_add_input(&tx,
            "1111111111111111111111111111111111111111111111111111111111111111", 0) ||
        !kw_tx_add_output(&tx, 1000000, spk, sizeof spk) ||
        !kw_tx_sign_p2pkh(&tx, 0, child.key + 1, spk, sizeof spk)) {
        fprintf(stderr, "consumer: sign\n"); return 1;
    }
    raw_n = kw_tx_serialize(&tx, raw, sizeof raw);
    if (!raw_n) { fprintf(stderr, "consumer: serialize\n"); return 1; }

    if (kw_slip39_split(seed, sizeof seed, "", 0, 1, &g, 1,
                        &shares[0][0], KW_SLIP39_MNEMONIC_MAX, &ns) != KW_SLIP39_OK ||
        ns != 3) {
        fprintf(stderr, "consumer: slip39\n"); return 1;
    }
    if (kw_codex32_split(seed, sizeof seed, "kw00", 2, 3,
                         cx, KW_CODEX32_MAX_LEN, &nc) != KW_CODEX32_OK || nc != 3) {
        fprintf(stderr, "consumer: codex32\n"); return 1;
    }

    kw_ec_stop();
    printf("consumer ok: %s, a %zu-byte spend signed, %zu slip39 and %zu codex32 "
           "shares,\n  built against the installed prefix with koinu %s\n",
           addr, raw_n, ns, nc, KW_VERSION);
    return 0;
}
