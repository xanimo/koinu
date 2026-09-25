/* koinu.dog - BIP39 tests
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
    int elen = (int)kw_test_unhex(ent_hex, ent);

    char m[KW_BIP39_MNEMONIC_MAX];
    if (!kw_bip39_from_entropy(ent, elen, m, sizeof m) || strcmp(m, mnemonic) != 0) {
        fprintf(stderr, "FAIL from_entropy %s\n  got  %s\n  want %s\n", ent_hex, m, mnemonic);
        fails++; return;
    }
    if (!kw_bip39_check(mnemonic)) { fprintf(stderr, "FAIL check %s\n", ent_hex); fails++; }

    uint8_t back[32]; size_t bl = 0;
    if (!kw_bip39_to_entropy(mnemonic, back, sizeof back, &bl) ||
        bl != (size_t)elen || memcmp(back, ent, elen) != 0) {
        fprintf(stderr, "FAIL to_entropy round trip %s\n", ent_hex); fails++;
    }
    if (seed_hex) {
        uint8_t seed[64];
        kw_bip39_to_seed(mnemonic, "TREZOR", seed);
        kw_test_check("seed", seed, 64, seed_hex);
    }
}

int main(void)
{
    /* the vendored array must reproduce the official file, byte for byte */
    {
        kw_sha256_ctx c; kw_sha256_init(&c);
        for (int i = 0; i < 2048; i++) {
            kw_sha256_update(&c, KW_BIP39_WORDLIST_EN[i], strlen(KW_BIP39_WORDLIST_EN[i]));
            kw_sha256_update(&c, "\n", 1);
        }
        uint8_t h[32];
        kw_sha256_final(&c, h);
        kw_test_check("wordlist sha256", h, 32,
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

    /* Spacing a phrase differently must not change the wallet. parse_words
       accepts these, so before the seed was built from the parsed words they
       each restored somewhere else in silence. The seed is the first vector's,
       with the empty passphrase. */
    {
        static const char *canon =
            "abandon abandon abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon about";
        static const char *spaced[] = {
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about ",
            " abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "abandon  abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        };
        uint8_t want[64];
        if (!kw_bip39_to_seed(canon, "", want)) { fprintf(stderr, "FAIL: canon seed\n"); fails++; }
        kw_test_check("canonical seed", want, 64,
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
            "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4");
        for (size_t i = 0; i < sizeof spaced / sizeof *spaced; i++) {
            uint8_t got[64];
            if (!kw_bip39_check(spaced[i])) { fprintf(stderr, "FAIL: check rejected [%s]\n", spaced[i]); fails++; continue; }
            if (!kw_bip39_to_seed(spaced[i], "", got) || memcmp(got, want, 64) != 0) {
                fprintf(stderr, "FAIL: spacing changed the seed [%s]\n", spaced[i]); fails++;
            }
        }
        /* a phrase whose words cannot be parsed has no seed to give */
        uint8_t got[64];
        if (kw_bip39_to_seed("abandon notaword about", "", got)) {
            fprintf(stderr, "FAIL: seeded from an unparseable phrase\n"); fails++;
        }
    }

    /* a tampered checksum must be rejected */
    if (kw_bip39_check("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon")) {
        fprintf(stderr, "FAIL: bad checksum accepted\n"); fails++;
    }
    /* an unknown word must be rejected */
    if (kw_bip39_check("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword")) {
        fprintf(stderr, "FAIL: unknown word accepted\n"); fails++;
    }

    /* generate must produce a self-consistent phrase */
    {
        char m[KW_BIP39_MNEMONIC_MAX];
        if (!kw_bip39_generate(16, m, sizeof m) || !kw_bip39_check(m)) {
            fprintf(stderr, "FAIL: generated mnemonic invalid\n"); fails++;
        }
    }

    if (fails || kw_test_fails()) {
        fprintf(stderr, "%d bip39 failure(s)\n", fails + kw_test_fails());
        return 1;
    }
    printf("bip39 ok: wordlist hash, trezor vectors, round trips, checksum rejection, generate,\n"
           "  and spacing that check accepts cannot move the seed\n");
    return 0;
}
