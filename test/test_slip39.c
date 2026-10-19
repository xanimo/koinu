/* koinu.dog - SLIP-39 tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Verifies the vendored wordlist reproduces the canonical file hash, runs the
 * 45 official vectors including the 30 that must be refused, checks the
 * recovered secret against the vector's xprv, then splits and recombines a
 * 64-byte seed across the group and member shapes koinu offers. */

#include "bip32.h"
#include "ec.h"
#include "sha2.h"
#include "slip39.h"
#include "testutil.h"
#include "wordlist_slip39.h"

#include "slip39_vectors.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails = 0;

static void fail(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    fprintf(stderr, "FAIL ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    fails++;
}

/* The spec names the BIP32 master seed as the secret to split, so a vector's
   xprv is the thing that proves the recovered bytes are that seed. */
static void check_xprv(const char *name, const uint8_t *ms, size_t mslen, const char *want)
{
    const kw_bip32_version btc = { 0x0488ade4u, 0x0488b21eu };
    kw_bip32_key master;
    char got[128];

    if (!kw_bip32_from_seed(ms, mslen, btc, &master)) {
        fail("%s: master key from the recovered secret", name);
        return;
    }
    if (!kw_bip32_serialize(&master, got, sizeof got) || strcmp(got, want) != 0) {
        fail("%s: xprv\n  got  %s\n  want %s", name, got, want);
    }
}

static void vectors(void)
{
    size_t v;

    for (v = 0; v < sizeof KW_SLIP39_VECTORS / sizeof *KW_SLIP39_VECTORS; v++) {
        const kw_slip39_vector *t = &KW_SLIP39_VECTORS[v];
        uint8_t ms[KW_SLIP39_MAX_SECRET], want[KW_SLIP39_MAX_SECRET];
        size_t mslen = 0, wantlen;
        kw_slip39_err err;

        err = kw_slip39_combine(t->mnemonics, t->nmnemonics, "TREZOR",
                                ms, sizeof ms, &mslen);

        if (t->secret[0] == '\0') {
            if (err == KW_SLIP39_OK)
                fail("%s: combined a set that must be refused", t->name);
            continue;
        }

        if (err != KW_SLIP39_OK) {
            fail("%s: %s", t->name, kw_slip39_strerror(err));
            continue;
        }

        wantlen = kw_test_unhex(t->secret, want);
        if (mslen != wantlen || memcmp(ms, want, wantlen) != 0) {
            fail("%s: wrong secret", t->name);
            continue;
        }

        check_xprv(t->name, ms, mslen, t->xprv);
    }
}

/* Split, then hand back exactly the shares a threshold needs and no more. */
static void roundtrip(const char *name, const uint8_t *ms, size_t mslen,
                      const char *pass, uint8_t e,
                      uint8_t gt, const kw_slip39_group *groups, size_t ngroups)
{
    char *buf = malloc(KW_SLIP39_MAX_TOTAL * KW_SLIP39_MNEMONIC_MAX);
    const char *pick[KW_SLIP39_MAX_TOTAL];
    uint8_t back[KW_SLIP39_MAX_SECRET];
    size_t n = 0, backlen = 0, npick = 0, i, g, base = 0;
    kw_slip39_err err;

    if (!buf) { fail("%s: out of memory", name); return; }

    err = kw_slip39_split(ms, mslen, pass, e, gt, groups, ngroups,
                          buf, KW_SLIP39_MNEMONIC_MAX, &n);
    if (err != KW_SLIP39_OK) {
        fail("%s: split: %s", name, kw_slip39_strerror(err));
        free(buf);
        return;
    }

    for (g = 0; g < ngroups; g++) {
        if (g < gt)
            for (i = 0; i < groups[g].threshold; i++)
                pick[npick++] = buf + (base + i) * KW_SLIP39_MNEMONIC_MAX;
        base += groups[g].count;
    }
    if (base != n) fail("%s: split wrote %zu mnemonics, wanted %zu", name, n, base);

    err = kw_slip39_combine(pick, npick, pass, back, sizeof back, &backlen);
    if (err != KW_SLIP39_OK)
        fail("%s: combine: %s", name, kw_slip39_strerror(err));
    else if (backlen != mslen || memcmp(back, ms, mslen) != 0)
        fail("%s: recovered a different secret", name);

    /* One share short of a threshold, and one share more. */
    if (npick > 1) {
        err = kw_slip39_combine(pick, npick - 1, pass, back, sizeof back, &backlen);
        if (err != KW_SLIP39_GROUPING)
            fail("%s: a short set gave %s", name, kw_slip39_strerror(err));
    }
    if (groups[0].count > groups[0].threshold && gt == 1) {
        pick[npick] = buf + groups[0].threshold * KW_SLIP39_MNEMONIC_MAX;
        err = kw_slip39_combine(pick, npick + 1, pass, back, sizeof back, &backlen);
        if (err != KW_SLIP39_GROUPING)
            fail("%s: a spare share gave %s", name, kw_slip39_strerror(err));
    }

    /* A wrong passphrase yields a different secret rather than an error, which
       is the property the threat model has to state. */
    if (pass[0] == '\0') {
        err = kw_slip39_combine(pick, npick, "x", back, sizeof back, &backlen);
        if (err != KW_SLIP39_OK)
            fail("%s: a wrong passphrase gave %s", name, kw_slip39_strerror(err));
        else if (backlen == mslen && memcmp(back, ms, mslen) == 0)
            fail("%s: a wrong passphrase recovered the secret", name);
    }

    free(buf);
}

static void encode_roundtrip(void)
{
    kw_slip39_share s, back;
    char m[KW_SLIP39_MNEMONIC_MAX];
    size_t lens[3] = { 16, 32, 64 }, i, k;

    for (i = 0; i < 3; i++) {
        memset(&s, 0, sizeof s);
        s.id = 0x7fff;
        s.ext = 1;
        s.e = 15;
        s.group_index = 9;
        s.group_threshold = 11;
        s.group_count = 13;
        s.member_index = 7;
        s.member_threshold = 5;
        s.valuelen = lens[i];
        for (k = 0; k < lens[i]; k++) s.value[k] = (uint8_t)(0xa0 + k);

        if (kw_slip39_encode(&s, m, sizeof m) != KW_SLIP39_OK) {
            fail("encode %zu-byte share", lens[i]);
            continue;
        }
        if (kw_slip39_decode(m, &back) != KW_SLIP39_OK) {
            fail("decode %zu-byte share", lens[i]);
            continue;
        }
        if (memcmp(&s, &back, sizeof s) != 0)
            fail("%zu-byte share did not survive the round trip", lens[i]);
    }

    /* 59 words for a 512-bit secret is the length Trezor's firmware refuses. */
    {
        size_t words = 1;
        const char *p;
        memset(&s, 0, sizeof s);
        s.ext = 1;
        s.group_threshold = s.group_count = s.member_threshold = 1;
        s.valuelen = 64;
        if (kw_slip39_encode(&s, m, sizeof m) != KW_SLIP39_OK) { fail("encode 64-byte"); return; }
        for (p = m; *p; p++) if (*p == ' ') words++;
        if (words != 59) fail("a 512-bit share is %zu words, wanted 59", words);
    }
}

static void rejections(void)
{
    /* Vector 1, which combines on its own. */
    const char *good = KW_SLIP39_VECTORS[0].mnemonics[0];
    uint8_t ms[KW_SLIP39_MAX_SECRET];
    size_t mslen = 0;
    char m[KW_SLIP39_MNEMONIC_MAX];
    kw_slip39_err err;

    struct { const char *why; const char *mnemonic; kw_slip39_err want; } cases[] = {
        { "unknown word", "duckling enlarge academic academic agency result length solution "
                          "fridge kidney coal piece deal husband erode duke ajar critical "
                          "decision koinu", KW_SLIP39_WORD },
        { "too few words", "duckling enlarge academic", KW_SLIP39_LENGTH },
        { "empty", "", KW_SLIP39_LENGTH },
    };
    size_t i;

    for (i = 0; i < sizeof cases / sizeof *cases; i++) {
        kw_slip39_share s;
        err = kw_slip39_decode(cases[i].mnemonic, &s);
        if (err != cases[i].want)
            fail("decode %s gave %s", cases[i].why, kw_slip39_strerror(err));
    }

    /* The same share twice is one member index twice, not a threshold. */
    {
        const char *two[2];
        const char *pair[2];
        const kw_slip39_vector *t = &KW_SLIP39_VECTORS[19];   /* another backup */

        two[0] = good;
        two[1] = good;
        err = kw_slip39_combine(two, 2, "TREZOR", ms, sizeof ms, &mslen);
        if (err != KW_SLIP39_GROUPING)
            fail("a duplicated share gave %s", kw_slip39_strerror(err));

        /* Shares from different backups share no id. */
        pair[0] = good;
        pair[1] = t->mnemonics[0];
        err = kw_slip39_combine(pair, 2, "TREZOR", ms, sizeof ms, &mslen);
        if (err != KW_SLIP39_GROUPING)
            fail("shares from two backups gave %s", kw_slip39_strerror(err));
    }

    /* A non-ASCII passphrase is refused rather than hashed as bytes, since the
       spec's interoperability rests on the character set. */
    {
        const char *one[1] = { good };
        err = kw_slip39_combine(one, 1, "pa\xc3\xa9ss", ms, sizeof ms, &mslen);
        if (err != KW_SLIP39_ARG)
            fail("a non-ASCII passphrase gave %s", kw_slip39_strerror(err));
    }

    /* Thresholds that are a threshold in name only. */
    {
        uint8_t seed[64];
        kw_slip39_group g2[2] = { { 1, 2 }, { 1, 1 } };
        kw_slip39_group g1[1] = { { 1, 2 } };
        char buf[2 * KW_SLIP39_MNEMONIC_MAX];
        size_t n = 0;

        memset(seed, 0x11, sizeof seed);
        if (kw_slip39_split(seed, sizeof seed, "", 0, 1, g1, 1,
                            buf, KW_SLIP39_MNEMONIC_MAX, &n) != KW_SLIP39_ARG)
            fail("split accepted a 1-of-2 member threshold");
        if (kw_slip39_split(seed, sizeof seed, "", 0, 1, g2, 2,
                            buf, KW_SLIP39_MNEMONIC_MAX, &n) != KW_SLIP39_ARG)
            fail("split accepted a 1-of-2 group threshold");
        if (kw_slip39_split(seed, 15, "", 0, 1, g1, 1,
                            buf, KW_SLIP39_MNEMONIC_MAX, &n) != KW_SLIP39_ARG)
            fail("split accepted a 15-byte secret");
    }

    /* A flipped word in the checksum must be caught, not corrected. */
    {
        const char *one[1] = { m };
        size_t len = strlen(good);

        if (len >= sizeof m) { fail("vector 1 does not fit"); return; }
        memcpy(m, good, len + 1);
        m[len - 1] = m[len - 1] == 'd' ? 'e' : 'd';       /* keyboard -> keyboare */
        err = kw_slip39_combine(one, 1, "TREZOR", ms, sizeof ms, &mslen);
        if (err != KW_SLIP39_WORD && err != KW_SLIP39_CHECKSUM)
            fail("a corrupted word gave %s", kw_slip39_strerror(err));
    }
}

/* The decoder against bytes nobody wrote: word sequences that are valid words
   in an invalid order, and arbitrary text. Fixed seed, so a crash reproduces by
   iteration number. Under make asan this is where a read past a word array or a
   bit cursor off the end of the share would show up. */
static void garbage(void)
{
    uint64_t st = 0x243f6a8885a308d3ULL;
    kw_slip39_share s;
    char m[KW_SLIP39_MNEMONIC_MAX * 2];
    int i;

    #define RND() (st ^= st << 13, st ^= st >> 7, st ^= st << 17, st)
    for (i = 0; i < 20000; i++) {
        size_t used = 0;
        int nw = 1 + (int)(RND() % 62), k;

        for (k = 0; k < nw; k++) {
            const char *w = KW_SLIP39_WORDLIST[RND() % 1024];
            size_t len = strlen(w);
            if (used + len + 2 > sizeof m) break;
            if (k) m[used++] = ' ';
            memcpy(m + used, w, len);
            used += len;
        }
        m[used] = '\0';
        (void)kw_slip39_decode(m, &s);
    }

    for (i = 0; i < 20000; i++) {
        size_t n = RND() % (sizeof m - 1), k;

        for (k = 0; k < n; k++) m[k] = (char)(32 + RND() % 95);
        m[n] = '\0';
        (void)kw_slip39_decode(m, &s);
    }
    #undef RND
}

int main(void)
{
    if (!kw_ec_start()) { fprintf(stderr, "no curve context\n"); return 1; }

    /* the vendored array must reproduce the official file, byte for byte */
    {
        kw_sha256_ctx c;
        uint8_t h[32];
        int i;

        kw_sha256_init(&c);
        for (i = 0; i < 1024; i++) {
            kw_sha256_update(&c, KW_SLIP39_WORDLIST[i], strlen(KW_SLIP39_WORDLIST[i]));
            kw_sha256_update(&c, "\n", 1);
        }
        kw_sha256_final(&c, h);
        kw_test_check("wordlist sha256", h, 32,
            "bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3");
    }

    vectors();
    encode_roundtrip();
    rejections();
    garbage();

    {
        uint8_t seed[64];
        size_t i;
        kw_slip39_group one[1]   = { { 1, 1 } };
        kw_slip39_group two[1]   = { { 2, 3 } };
        kw_slip39_group five[1]  = { { 5, 16 } };
        kw_slip39_group multi[3] = { { 1, 1 }, { 2, 3 }, { 3, 5 } };
        kw_slip39_group big[16];

        for (i = 0; i < sizeof seed; i++) seed[i] = (uint8_t)(i * 7 + 1);
        for (i = 0; i < 16; i++) { big[i].threshold = 2; big[i].count = 2; }

        roundtrip("1-of-1", seed, sizeof seed, "", 0, 1, one, 1);
        roundtrip("2-of-3", seed, sizeof seed, "", 0, 1, two, 1);
        roundtrip("2-of-3 with a passphrase", seed, sizeof seed, "koinu", 0, 1, two, 1);
        roundtrip("5-of-16", seed, sizeof seed, "", 0, 1, five, 1);
        roundtrip("2 of 3 groups", seed, sizeof seed, "", 0, 2, multi, 3);
        roundtrip("16 groups", seed, sizeof seed, "", 0, 16, big, 16);
        roundtrip("128-bit secret", seed, 16, "", 0, 1, two, 1);
        roundtrip("160-bit secret", seed, 20, "", 0, 1, two, 1);
        roundtrip("exponent 2", seed, sizeof seed, "", 2, 1, two, 1);
    }

    if (fails || kw_test_fails()) {
        fprintf(stderr, "slip39: %d failures\n", fails + kw_test_fails());
        return 1;
    }
    printf("slip39 ok\n");
    return 0;
}
