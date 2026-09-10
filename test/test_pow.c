/* koinu.dog - proof of work tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * The compact encoding is checked against Bitcoin's own SetCompact vectors, which
 * are the ones that pin down the awkward cases: a mantissa shifted away to
 * nothing, the sign bit, and a mantissa that runs off the top of 256 bits. The
 * targets and work values are computed independently rather than taken from this
 * code. The end of the file is the whole rule on real data: Dogecoin's block 1,
 * hashed with scrypt, against the nBits in its own header.
 *
 * Targets are written here in display order, most significant byte first, and
 * reversed before comparing, since a 256-bit value in this tree is internal
 * order end to end. */

#include "pow.h"
#include "chainparams.h"
#include "scrypt.h"
#include "sha2.h"
#include "testutil.h"

#include <stdio.h>
#include <string.h>

static int fail;

/* (want) is display order: reverse it into the internal order kw_u256 uses */
static int is(const char *what, const kw_u256 *got, const char *want)
{
    uint8_t w[32], g[32];
    if (kw_test_unhex(want, w) != 32) { fprintf(stderr, "FAIL: %s bad vector\n", what); return 0; }
    for (int i = 0; i < 16; i++) { uint8_t t = w[i]; w[i] = w[31 - i]; w[31 - i] = t; }
    kw_u256_to_bytes(got, g);
    if (memcmp(g, w, 32) != 0) {
        fprintf(stderr, "FAIL: %s\n  got  ", what);
        for (int i = 31; i >= 0; i--) fprintf(stderr, "%02x", g[i]);
        fprintf(stderr, "\n  want %s\n", want);
        return 0;
    }
    return 1;
}

static void target_is(uint32_t bits, const char *want)
{
    kw_u256 t;
    char what[64];
    snprintf(what, sizeof what, "target of %08x", bits);
    if (!kw_bits_target(bits, &t)) { fprintf(stderr, "FAIL: %s rejected\n", what); fail = 1; return; }
    if (!is(what, &t, want)) fail = 1;
}

static void rejects(uint32_t bits)
{
    kw_u256 t;
    if (kw_bits_target(bits, &t)) { fprintf(stderr, "FAIL: %08x accepted\n", bits); fail = 1; }
}

static void work_is(uint32_t bits, const char *want)
{
    kw_u256 w;
    char what[64];
    snprintf(what, sizeof what, "work of %08x", bits);
    if (!kw_bits_work(bits, &w)) { fprintf(stderr, "FAIL: %s rejected\n", what); fail = 1; return; }
    if (!is(what, &w, want)) fail = 1;
}

int main(void)
{
    /* Bitcoin's arith_uint256 SetCompact vectors. A mantissa of zero, or one the
       exponent shifts away entirely, is not a target a header may carry. */
    rejects(0x00123456); rejects(0x01003456); rejects(0x02000056);
    rejects(0x03000000); rejects(0x04000000);
    rejects(0x00923456); rejects(0x01803456);       /* sign bit set */
    rejects(0x04923456);
    rejects(0xff123456);                            /* off the top */
    rejects(0x22001234);                            /* off the top, small exponent */

    target_is(0x01123456, "0000000000000000000000000000000000000000000000000000000000000012");
    target_is(0x02123456, "0000000000000000000000000000000000000000000000000000000000001234");
    target_is(0x03123456, "0000000000000000000000000000000000000000000000000000000000123456");
    target_is(0x04123456, "0000000000000000000000000000000000000000000000000000000012345600");
    target_is(0x05009234, "0000000000000000000000000000000000000000000000000000000092340000");
    target_is(0x20123456, "1234560000000000000000000000000000000000000000000000000000000000");
    target_is(0x21008000, "8000000000000000000000000000000000000000000000000000000000000000");
    target_is(0x22000001, "0100000000000000000000000000000000000000000000000000000000000000");

    /* difficulty 1 on each chain */
    target_is(0x1d00ffff, "00000000ffff0000000000000000000000000000000000000000000000000000");
    target_is(0x1e0ffff0, "00000ffff0000000000000000000000000000000000000000000000000000000");

    /* 2^256/(target+1). The first is Bitcoin's genesis chain work, which is the
       one value of these that can be read off a running node. */
    work_is(0x1d00ffff, "0000000000000000000000000000000000000000000000000000000100010001");
    work_is(0x1e0ffff0, "0000000000000000000000000000000000000000000000000000000000100010");
    work_is(0x1b0404cb, "00000000000000000000000000000000000000000000000000003fb3ab764c00");
    work_is(0x1a021ca4, "0000000000000000000000000000000000000000000000000079381a936cd392");

    /* summing work across a chain, and the carry that says it wrapped */
    {
        kw_u256 acc, one;
        if (!kw_bits_work(0x1e0ffff0, &acc)) { fprintf(stderr, "FAIL: work call\n"); return 1; }
        kw_u256 w = acc;
        if (kw_u256_add(&acc, &w) || kw_u256_add(&acc, &w))
            { fprintf(stderr, "FAIL: three works should not carry out\n"); return 1; }
        if (!is("three blocks of work", &acc, "0000000000000000000000000000000000000000000000000000000000300030")) return 1;

        /* a carry out of the top must be reported rather than folded away */
        kw_u256 full;
        for (int i = 0; i < 8; i++) full.w[i] = 0xffffffffu;
        kw_u256_zero(&one);
        one.w[0] = 1;
        if (!kw_u256_add(&full, &one)) { fprintf(stderr, "FAIL: wrap not reported\n"); return 1; }
        if (!kw_u256_is_zero(&full)) { fprintf(stderr, "FAIL: wrap did not wrap\n"); return 1; }
    }

    /* a canonical encoding round-trips; one whose low bytes the exponent throws
       away comes back without them, which is the whole of what lossy means here */
    {
        /* both from Bitcoin's suite: low bytes the exponent drops, and a mantissa
           padded with a leading zero byte */
        static const struct { uint32_t in, out; } lossy[] = {
            { 0x01123456, 0x01120000 }, { 0x22000001, 0x20010000 }
        };
        for (size_t i = 0; i < sizeof lossy / sizeof *lossy; i++) {
            kw_u256 t;
            if (!kw_bits_target(lossy[i].in, &t)) { fprintf(stderr, "FAIL: decode\n"); return 1; }
            uint32_t back = kw_target_bits(&t);
            if (back != lossy[i].out) {
                fprintf(stderr, "FAIL: %08x re-encoded as %08x, wanted %08x\n",
                        lossy[i].in, back, lossy[i].out);
                return 1;
            }
        }
    }
    {
        static const uint32_t canonical[] = { 0x1d00ffff, 0x1e0ffff0, 0x1b0404cb,
                                              0x1a021ca4, 0x20123456, 0x21008000 };
        for (size_t i = 0; i < sizeof canonical / sizeof *canonical; i++) {
            kw_u256 t;
            if (!kw_bits_target(canonical[i], &t)) { fprintf(stderr, "FAIL: decode\n"); return 1; }
            uint32_t back = kw_target_bits(&t);
            if (back != canonical[i]) {
                fprintf(stderr, "FAIL: %08x re-encoded as %08x\n", canonical[i], back);
                return 1;
            }
        }
    }

    /* Dogecoin's genesis block, which is the one header whose bytes this tree can
       prove genuine without asking a peer: sha256d of them has to come out equal
       to the genesis hash chainparams compiles in. Then its scrypt hash has to
       meet the nBits it carries, which is the whole rule on real data. */
    uint8_t hdr[80];
    if (kw_test_unhex(
            "010000000000000000000000000000000000000000000000000000000000000000"
            "000000696ad20e2dd4365c7459b4a4a5af743d5e92c6da3229e6532cd605f6533f"
            "2a5b24a6a152f0ff0f1e67860100", hdr) != 80)
        { fprintf(stderr, "FAIL: header vector\n"); return 1; }

    uint8_t once[32], id[32], want[32];
    kw_sha256(hdr, 80, once);
    kw_sha256(once, 32, id);
    if (kw_test_unhex(KW_DOGE_MAINNET.genesis, want) != 32)
        { fprintf(stderr, "FAIL: genesis constant\n"); return 1; }
    for (int i = 0; i < 16; i++) { uint8_t t = want[i]; want[i] = want[31 - i]; want[31 - i] = t; }
    if (memcmp(id, want, 32) != 0) {
        fprintf(stderr, "FAIL: these 80 bytes are not genesis\n  got  ");
        for (int i = 31; i >= 0; i--) fprintf(stderr, "%02x", id[i]);
        fprintf(stderr, "\n  want %s\n", KW_DOGE_MAINNET.genesis);
        return 1;
    }

    uint32_t bits = kw_header_bits(hdr);
    if (bits != 0x1e0ffff0) { fprintf(stderr, "FAIL: nBits read as %08x\n", bits); return 1; }

    uint8_t pow[32];
    if (!kw_scrypt_pow(hdr, pow, NULL)) { fprintf(stderr, "FAIL: scrypt call\n"); return 1; }
    if (!kw_pow_check(pow, bits)) {
        fprintf(stderr, "FAIL: genesis does not meet its own target\n  pow ");
        for (int i = 31; i >= 0; i--) fprintf(stderr, "%02x", pow[i]);
        fprintf(stderr, "\n");
        return 1;
    }

    /* the same header with the nonce moved does not, which is what says the check
       compares rather than always passing */
    uint8_t bad[80];
    memcpy(bad, hdr, 80);
    bad[76] ^= 1;
    if (!kw_scrypt_pow(bad, pow, NULL)) { fprintf(stderr, "FAIL: scrypt call\n"); return 1; }
    if (kw_pow_check(pow, bits))
        { fprintf(stderr, "FAIL: a different nonce also met the target\n"); return 1; }

    /* and genesis misses Bitcoin's difficulty 1, which is 256 times harder */
    if (!kw_scrypt_pow(hdr, pow, NULL)) { fprintf(stderr, "FAIL: scrypt call\n"); return 1; }
    if (kw_pow_check(pow, 0x1d00ffff))
        { fprintf(stderr, "FAIL: genesis met bitcoin's difficulty 1\n"); return 1; }

    if (fail) return 1;
    printf("pow ok: 10 rejected encodings, 10 targets, 4 work values, 6 round trips and 2 lossy,\n"
           "  genesis verified by sha256d against chainparams, meets 1e0ffff0 under scrypt,\n  and misses it with the nonce moved\n");
    return 0;
}
