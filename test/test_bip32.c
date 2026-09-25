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
        if (!kw_bip32_parse(xprv, btc, &p)) { fprintf(stderr, "FAIL: parse xprv\n"); return 1; }
        chk(&p, xprv, "parse->serialize round trip");

        /* BIP32 test vector 5: every one of these must be refused. */
        static const struct { const char *key, *why; } bad[] = {
        { "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm",
          "pubkey version / prvkey mismatch" },
        { "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGTQQD3dC4H2D5GBj7vWvSQaaBv5cxi9gafk7NF3pnBju6dwKvH",
          "prvkey version / pubkey mismatch" },
        { "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn",
          "invalid pubkey prefix 04" },
        { "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGpWnsj83BHtEy5Zt8CcDr1UiRXuWCmTQLxEK9vbz5gPstX92JQ",
          "invalid prvkey prefix 04" },
        { "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6N8ZMMXctdiCjxTNq964yKkwrkBJJwpzZS4HS2fxvyYUA4q2Xe4",
          "invalid pubkey prefix 01" },
        { "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fEQ3Qen6J",
          "invalid prvkey prefix 01" },
        { "xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fhZMBoG3G4ZW1N2kZuHEPY53qmbZzCHshoQnNf4GvELZfqTUrcv",
          "zero depth with non-zero parent fingerprint" },
        { "xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGENhYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ",
          "zero depth with non-zero parent fingerprint" },
        { "xprv9s21ZrQH4r4TsiLvyLXqM9P7k1K3EYhA1kkD6xuquB5i39AU8KF42acDyL3qsDbU9NmZn6MsGSUYZEsuoePmjzsB3eFKSUEh3Gu1N3cqVUN",
          "zero depth with non-zero index" },
        { "xpub661MyMwAuDcm6CRQ5N4qiHKrJ39Xe1R1NyfouMKTTWcguwVcfrZJaNvhpebzGerh7gucBvzEQWRugZDuDXjNDRmXzSZe4c7mnTK97pTvGS8",
          "zero depth with non-zero index" },
        { "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4",
          "unknown extended key version" },
        { "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9",
          "unknown extended key version" },
        { "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx",
          "private key 0 not in 1..n-1" },
        { "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD5SDKr24z3aiUvKr9bJpdrcLg1y3G",
          "private key n not in 1..n-1" },
        { "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Q5JXayek4PRsn35jii4veMimro1xefsM58PgBMrvdYre8QyULY",
          "invalid pubkey, not on the curve" },
        { "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL",
          "invalid checksum" },
        };
        for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
            kw_bip32_key q;
            if (kw_bip32_parse(bad[i].key, btc, &q)) {
                fprintf(stderr, "FAIL: accepted an invalid key (%s)\n", bad[i].why);
                fails++;
            }
        }
        /* the right key under another network's versions is not this wallet's */
        kw_bip32_version other = { 0x02fac398, 0x02facafd };
        if (kw_bip32_parse(xprv, other, &p)) {
            fprintf(stderr, "FAIL: accepted a foreign version\n"); fails++;
        }
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
           "  16 invalid keys from vector 5 and a foreign version refused,\n"
           "  and every public-key operation refuses with no curve context\n");
    return 0;
}
