/* dogewallet - BIP39 tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Verifies the vendored wordlist reproduces the canonical file hash, then runs
 * the Trezor BIP39 vectors (entropy -> mnemonic -> seed) with round-trips. */

#include "bip39.h"
#include "sha2.h"
#include "testutil.h"
#include "wordlist_en.h"

#include <stdio.h>
#include <string.h>

static int fails = 0;

static void vector(const char *ent_hex, const char *mnemonic, const char *seed_hex)
{
    uint8_t ent[32];
    int elen = (int)dw_test_unhex(ent_hex, ent);

    char m[DW_BIP39_MNEMONIC_MAX];
    if (!dw_bip39_from_entropy(ent, elen, m, sizeof m) || strcmp(m, mnemonic) != 0) {
        fprintf(stderr, "FAIL from_entropy %s\n  got  %s\n  want %s\n", ent_hex, m, mnemonic);
        fails++; return;
    }
    if (!dw_bip39_check(mnemonic)) { fprintf(stderr, "FAIL check %s\n", ent_hex); fails++; }

    uint8_t back[32]; size_t bl = 0;
    if (!dw_bip39_to_entropy(mnemonic, back, sizeof back, &bl) ||
        bl != (size_t)elen || memcmp(back, ent, elen) != 0) {
        fprintf(stderr, "FAIL to_entropy round trip %s\n", ent_hex); fails++;
    }
    if (seed_hex) {
        uint8_t seed[64];
        dw_bip39_to_seed(mnemonic, "TREZOR", seed);
        dw_test_check("seed", seed, 64, seed_hex);
    }
}

int main(void)
{
    /* the vendored array must reproduce the official file, byte for byte */
    {
        dw_sha256_ctx c; dw_sha256_init(&c);
        for (int i = 0; i < 2048; i++) {
            dw_sha256_update(&c, DW_BIP39_WORDLIST_EN[i], strlen(DW_BIP39_WORDLIST_EN[i]));
            dw_sha256_update(&c, "\n", 1);
        }
        uint8_t h[32];
        dw_sha256_final(&c, h);
        dw_test_check("wordlist sha256", h, 32,
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda");
    }

    vector("00000000000000000000000000000000",
           "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
           "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
           "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04");

    vector("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
           "legal winner thank year wave sausage worth useful legal winner thank yellow",
           "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6f"
           "a457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607");

    vector("ffffffffffffffffffffffffffffffff",
           "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong", NULL);

    vector("0000000000000000000000000000000000000000000000000000000000000000",
           "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
           "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
           "abandon abandon abandon abandon abandon art", NULL);

    /* a tampered checksum must be rejected */
    if (dw_bip39_check("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon")) {
        fprintf(stderr, "FAIL: bad checksum accepted\n"); fails++;
    }
    /* an unknown word must be rejected */
    if (dw_bip39_check("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword")) {
        fprintf(stderr, "FAIL: unknown word accepted\n"); fails++;
    }

    /* generate must produce a self-consistent phrase */
    {
        char m[DW_BIP39_MNEMONIC_MAX];
        if (!dw_bip39_generate(16, m, sizeof m) || !dw_bip39_check(m)) {
            fprintf(stderr, "FAIL: generated mnemonic invalid\n"); fails++;
        }
    }

    if (fails || dw_test_fails()) {
        fprintf(stderr, "%d bip39 failure(s)\n", fails + dw_test_fails());
        return 1;
    }
    printf("bip39 ok: wordlist hash, trezor vectors, round trips, checksum rejection, generate\n");
    return 0;
}
