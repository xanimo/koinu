/* koinu.dog - secp256k1 wrapper tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "ec.h"
#include "sha2.h"
#include "testutil.h"

#include <stdio.h>
#include <string.h>

/* S -> n-S, re-encoded as DER. The other valid signature over the same message: what
   a third party can produce without the key, and what low-S exists to refuse. */
static size_t flip_s(const uint8_t *in, size_t inlen, uint8_t *out)
{
    static const uint8_t N[32] = {
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
        0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x41
    };
    if (inlen < 8 || in[0] != 0x30) return 0;
    size_t rl = in[3], sl = in[5 + rl];
    const uint8_t *S = in + 6 + rl;
    if (sl > 33 || 6 + rl + sl != inlen) return 0;

    uint8_t s32[32], flipped[32];
    memset(s32, 0, sizeof s32);
    size_t skip = (sl == 33) ? 1 : 0;
    memcpy(s32 + 32 - (sl - skip), S + skip, sl - skip);

    int borrow = 0;
    for (int i = 31; i >= 0; i--) {
        int d = (int)N[i] - (int)s32[i] - borrow;
        borrow = d < 0;
        flipped[i] = (uint8_t)(d + (borrow ? 256 : 0));
    }

    size_t lead = 0;
    while (lead < 31 && flipped[lead] == 0) lead++;
    int pad = (flipped[lead] & 0x80) ? 1 : 0;
    size_t hs = 32 - lead + (size_t)pad, n = 0;
    out[n++] = 0x30;
    out[n++] = (uint8_t)(4 + rl + hs);
    out[n++] = 0x02;
    out[n++] = (uint8_t)rl;
    memcpy(out + n, in + 4, rl); n += rl;
    out[n++] = 0x02;
    out[n++] = (uint8_t)hs;
    if (pad) out[n++] = 0x00;
    memcpy(out + n, flipped + lead, 32 - lead); n += 32 - lead;
    return n;
}

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
    kw_sha256("koinu ec seckey", 15, sk);
    if (!kw_ec_seckey_verify(sk)) { fprintf(stderr, "FAIL: derived sk invalid\n"); return 1; }
    kw_ec_pubkey(sk, pk);
    kw_sha256("a message to sign", 17, h);
    if (!kw_ec_sign(sk, h, sig, &siglen))   { fprintf(stderr, "FAIL: sign\n"); return 1; }
    if (!kw_ec_verify(pk, h, sig, siglen))  { fprintf(stderr, "FAIL: verify good sig\n"); return 1; }
    h[0] ^= 1;
    if (kw_ec_verify(pk, h, sig, siglen))   { fprintf(stderr, "FAIL: verify accepted tampered hash\n"); return 1; }
    h[0] ^= 1;


    /* Strict DER and low-S are not conveniences, they are what stops a third party
       flipping S to n-S and relaying the same spend under a different txid. A
       downstream now leans on this being enforced here, so a change that relaxed
       either would have to fail something: it fails this.
       The high-S form of a valid signature is still a valid ECDSA signature over the
       same message, which is the point. */
    {
        uint8_t high[KW_EC_SIG_DER_MAX], back[KW_EC_SIG_DER_MAX];
        size_t hn = flip_s(sig, siglen, high);
        if (!hn) { fprintf(stderr, "FAIL: could not build the high-S form\n"); return 1; }

        if (kw_ec_verify(pk, h, high, hn))
            { fprintf(stderr, "FAIL: a high-S signature was accepted\n"); return 1; }

        /* and it is refused for being high-S, not for being malformed: flipping it
           back has to reproduce the signature that does verify */
        size_t bn = flip_s(high, hn, back);
        if (bn != siglen || memcmp(back, sig, siglen) != 0)
            { fprintf(stderr, "FAIL: the flip is not its own inverse, so the high-S form is junk\n"); return 1; }
        if (!kw_ec_verify(pk, h, back, bn))
            { fprintf(stderr, "FAIL: flipped back and it no longer verifies\n"); return 1; }

        /* and the encoding itself has to be strict */
        uint8_t bad[KW_EC_SIG_DER_MAX];
        memcpy(bad, sig, siglen);
        bad[0] = 0x31;
        if (kw_ec_verify(pk, h, bad, siglen)) { fprintf(stderr, "FAIL: a bad DER tag was accepted\n"); return 1; }
        memcpy(bad, sig, siglen);
        bad[1]++;
        if (kw_ec_verify(pk, h, bad, siglen)) { fprintf(stderr, "FAIL: a wrong DER length was accepted\n"); return 1; }
        if (kw_ec_verify(pk, h, sig, siglen - 1))
            { fprintf(stderr, "FAIL: a truncated signature was accepted\n"); return 1; }
        memcpy(bad, sig, siglen);
        bad[siglen] = 0x00;
        if (kw_ec_verify(pk, h, bad, siglen + 1))
            { fprintf(stderr, "FAIL: a trailing byte was accepted\n"); return 1; }
    }

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
    printf("ec ok: G/2G vectors, sign+verify, rfc6979 determinism, tweak agreement,\n"
           "  high-S refused and its flip reversible, four malformed encodings refused\n");
    return 0;
}
