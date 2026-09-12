/* koinu.dog - BIP32 test vectors
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * BIP32 test vector 1 (seed 000102...0f) with Bitcoin's version bytes, plus the
 * derivation-agreement and serialize/parse round-trip properties. */

#include "bip32.h"
#include "ec.h"

#include <stdio.h>
#include <string.h>

static int fails = 0;

static void chk(const kw_bip32_key *k, const char *want, const char *name)
{
    char s[128];
    if (!kw_bip32_serialize(k, s, sizeof s) || strcmp(s, want) != 0) {
        fprintf(stderr, "FAIL %s\n  got  %s\n  want %s\n", name, s, want);
        fails++;
    }
}

int main(void)
{
    if (!kw_ec_start()) { fprintf(stderr, "FAIL: ec_start\n"); return 1; }

    kw_bip32_version btc = { 0x0488ade4, 0x0488b21e };
    uint8_t seed[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

    kw_bip32_key m, mpub;
    if (!kw_bip32_from_seed(seed, sizeof seed, btc, &m)) { fprintf(stderr, "FAIL: from_seed\n"); return 1; }
    kw_bip32_neuter(&m, &mpub);

    chk(&m,    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi", "m prv");
    chk(&mpub, "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8", "m pub");

    /* m/0' */
    kw_bip32_key h0, h0pub;
    if (!kw_bip32_ckd_priv(&m, KW_BIP32_HARDENED + 0, &h0)) { fprintf(stderr, "FAIL: ckd m/0'\n"); return 1; }
    kw_bip32_neuter(&h0, &h0pub);
    chk(&h0,    "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7", "m/0' prv");
    chk(&h0pub, "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw", "m/0' pub");

    /* m/0'/1 */
    kw_bip32_key h01, h01pub;
    if (!kw_bip32_ckd_priv(&h0, 1, &h01)) { fprintf(stderr, "FAIL: ckd m/0'/1\n"); return 1; }
    kw_bip32_neuter(&h01, &h01pub);
    chk(&h01,    "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs", "m/0'/1 prv");
    chk(&h01pub, "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ", "m/0'/1 pub");

    /* the path parser must reach the same node */
    kw_bip32_key viapath;
    if (!kw_bip32_derive_path(&m, "m/0'/1", &viapath)) { fprintf(stderr, "FAIL: derive_path\n"); return 1; }
    chk(&viapath, "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs", "derive_path m/0'/1");

    /* CKDpriv+neuter must equal CKDpub on a non-hardened index */
    kw_bip32_key a, an, b;
    if (!kw_bip32_ckd_priv(&m, 0, &a)) { fprintf(stderr, "FAIL: ckd m/0\n"); return 1; }
    kw_bip32_neuter(&a, &an);
    if (!kw_bip32_ckd_pub(&mpub, 0, &b)) { fprintf(stderr, "FAIL: ckd_pub m/0\n"); return 1; }
    {
        char sa[128], sb[128];
        kw_bip32_serialize(&an, sa, sizeof sa);
        kw_bip32_serialize(&b,  sb, sizeof sb);
        if (strcmp(sa, sb) != 0) {
            fprintf(stderr, "FAIL: private and public derivation disagree at m/0\n  %s\n  %s\n", sa, sb);
            fails++;
        }
    }

    /* parse round trip */
    {
        const char *xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        kw_bip32_key p;
        if (!kw_bip32_parse(xprv, &p)) { fprintf(stderr, "FAIL: parse xprv\n"); return 1; }
        chk(&p, xprv, "parse->serialize round trip");
    }

    kw_ec_stop();
    if (fails) { fprintf(stderr, "%d bip32 vector(s) failed\n", fails); return 1; }

    /* With no curve context, every operation that needs one must refuse rather than
       leave the caller's buffer as it found it. kw_bip32_pubkey used to return void
       and drop kw_ec_pubkey's failure, so a caller hashed its own stack: the context
       is down whenever the rng is, which a seccomp filter with no getrandom and no
       /dev/urandom is enough to cause. */
    kw_ec_stop();
    {
        uint8_t pub[33];
        memset(pub, 0xa5, sizeof pub);
        if (kw_bip32_pubkey(&m, pub)) { fprintf(stderr, "FAIL: pubkey without a context\n"); return 1; }
        for (int i = 0; i < 33; i++)
            if (pub[i] != 0xa5) { fprintf(stderr, "FAIL: the buffer was written anyway\n"); return 1; }

        kw_bip32_key child, neutered;
        if (kw_bip32_ckd_priv(&m, 0, &child))
            { fprintf(stderr, "FAIL: unhardened derivation without a context\n"); return 1; }
        if (kw_bip32_neuter(&m, &neutered))
            { fprintf(stderr, "FAIL: neuter without a context\n"); return 1; }
    }
    if (!kw_ec_start()) { fprintf(stderr, "FAIL: ec restart\n"); return 1; }

    printf("bip32 ok: vector 1 (m, m/0', m/0'/1), path parse, priv/pub agreement, round trip,\n"
           "  and every public-key operation refuses with no curve context\n");
    return 0;
}
