/* koinu.dog - PBKDF2-HMAC-SHA512 tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "pbkdf2.h"
#include "hmac.h"
#include "testutil.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    uint8_t out[64];

    /* One iteration must equal a single HMAC over salt||INT32BE(1). This checks
       the block indexing and assembly without needing an external vector. */
    {
        const char *p = "password", *s = "salt";
        kw_pbkdf2_hmac_sha512((const uint8_t *)p, strlen(p),
                              (const uint8_t *)s, strlen(s), 1, out, 64);
        uint8_t saltint[8];
        memcpy(saltint, s, 4);
        saltint[4] = 0; saltint[5] = 0; saltint[6] = 0; saltint[7] = 1;
        uint8_t direct[64];
        kw_hmac_sha512((const uint8_t *)p, strlen(p), saltint, sizeof saltint, direct);
        if (memcmp(out, direct, 64) != 0) {
            fprintf(stderr, "FAIL: c=1 does not match a direct hmac\n");
            return 1;
        }
    }

    /* Canonical BIP39 vector: mnemonic-to-seed with passphrase "TREZOR", which
       is 2048 rounds and exercises the xor loop against a known-good seed. */
    {
        const char *m = "abandon abandon abandon abandon abandon abandon abandon "
                        "abandon abandon abandon abandon about";
        const char *salt = "mnemonicTREZOR";
        kw_pbkdf2_hmac_sha512((const uint8_t *)m, strlen(m),
                              (const uint8_t *)salt, strlen(salt), 2048, out, 64);
        kw_test_check("bip39 seed (abandon..about / TREZOR)", out, 64,
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
            "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04");
    }

    if (kw_test_fails()) { fprintf(stderr, "%d pbkdf2 case(s) failed\n", kw_test_fails()); return 1; }
    printf("pbkdf2 ok: c=1 equals direct hmac, and the bip39 2048-round seed matches\n");
    return 0;
}
