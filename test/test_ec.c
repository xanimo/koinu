/* koinu.dog - secp256k1 wrapper tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "ec.h"
#include "sha2.h"
#include "testutil.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    if (!kw_ec_start()) { fprintf(stderr, "FAIL: ec_start\n"); return 1; }

    uint8_t pub[KW_EC_PUBKEY_LEN];

    /* privkey 1 is the generator G; privkey 2 is 2G. Fixed, checkable vectors. */
    uint8_t one[32] = {0}; one[31] = 1;
    uint8_t two[32] = {0}; two[31] = 2;
    kw_ec_pubkey(one, pub);
    kw_test_check("pubkey(1) == G", pub, 33,
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    kw_ec_pubkey(two, pub);
    kw_test_check("pubkey(2) == 2G", pub, 33,
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5");

    /* seckey validity: zero is not a key, one is. */
    uint8_t zero[32] = {0};
    if (kw_ec_seckey_verify(zero)) { fprintf(stderr, "FAIL: zero accepted as seckey\n"); return 1; }
    if (!kw_ec_seckey_verify(one))  { fprintf(stderr, "FAIL: one rejected as seckey\n"); return 1; }

    /* sign / verify round trip, and rejection of a tampered hash */
    uint8_t sk[32], pk[33], h[32], sig[KW_EC_SIG_DER_MAX];
    size_t siglen = 0;
    kw_sha256("koinu ec seckey", 20, sk);
    if (!kw_ec_seckey_verify(sk)) { fprintf(stderr, "FAIL: derived sk invalid\n"); return 1; }
    kw_ec_pubkey(sk, pk);
    kw_sha256("a message to sign", 17, h);
    if (!kw_ec_sign(sk, h, sig, &siglen))   { fprintf(stderr, "FAIL: sign\n"); return 1; }
    if (!kw_ec_verify(pk, h, sig, siglen))  { fprintf(stderr, "FAIL: verify good sig\n"); return 1; }
    h[0] ^= 1;
    if (kw_ec_verify(pk, h, sig, siglen))   { fprintf(stderr, "FAIL: verify accepted tampered hash\n"); return 1; }
    h[0] ^= 1;

    /* RFC 6979 determinism: signing the same thing twice is byte-identical */
    uint8_t sig2[KW_EC_SIG_DER_MAX]; size_t siglen2 = 0;
    kw_ec_sign(sk, h, sig2, &siglen2);
    if (siglen != siglen2 || memcmp(sig, sig2, siglen) != 0) {
        fprintf(stderr, "FAIL: signatures not deterministic\n"); return 1;
    }

    /* BIP32's core identity: deriving on the private side and the public side
       must agree, i.e. pubkey(sk + t) == pubkey(sk) + t*G */
    uint8_t tweak[32];
    kw_sha256("a child tweak", 13, tweak);
    uint8_t sk_t[32]; memcpy(sk_t, sk, 32);
    if (!kw_ec_seckey_tweak_add(sk_t, tweak)) { fprintf(stderr, "FAIL: seckey tweak\n"); return 1; }
    uint8_t pub_from_priv[33];
    kw_ec_pubkey(sk_t, pub_from_priv);
    uint8_t pub_tweaked[33]; memcpy(pub_tweaked, pk, 33);
    if (!kw_ec_pubkey_tweak_add(pub_tweaked, tweak)) { fprintf(stderr, "FAIL: pubkey tweak\n"); return 1; }
    if (memcmp(pub_from_priv, pub_tweaked, 33) != 0) {
        fprintf(stderr, "FAIL: private and public derivation disagree\n"); return 1;
    }

    kw_ec_stop();
    if (kw_test_fails()) { fprintf(stderr, "%d ec vector(s) failed\n", kw_test_fails()); return 1; }
    printf("ec ok: G/2G vectors, sign+verify, rfc6979 determinism, tweak agreement\n");
    return 0;
}
