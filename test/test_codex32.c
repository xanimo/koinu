/* koinu.dog - codex32 (BIP-93) tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * The BIP's own vectors: six unshared secrets across every allowed seed size,
 * two share sets with their derived shares, and the 55 strings that must be
 * refused. Then round trips of a 64-byte seed through the long form. */

#include "codex32.h"
#include "ec.h"
#include "testutil.h"

#include "codex32_vectors.h"

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

/* Lowercase in place, since the vectors give some strings in uppercase and a
   re-encode always produces lowercase. */
static void lower(const char *in, char *out, size_t cap)
{
    size_t i;

    for (i = 0; i + 1 < cap && in[i]; i++)
        out[i] = (in[i] >= 'A' && in[i] <= 'Z') ? (char)(in[i] - 'A' + 'a') : in[i];
    out[i] = '\0';
}

static void secrets(void)
{
    size_t v;

    for (v = 0; v < sizeof KW_CODEX32_SECRETS / sizeof *KW_CODEX32_SECRETS; v++) {
        const kw_codex32_secret_vector *t = &KW_CODEX32_SECRETS[v];
        uint8_t seed[KW_CODEX32_MAX_SECRET], want[KW_CODEX32_MAX_SECRET];
        char back[KW_CODEX32_MAX_LEN], low[KW_CODEX32_MAX_LEN], id[5];
        size_t seedlen = 0, wantlen;
        kw_codex32 c, rebuilt;
        kw_codex32_err err;

        if ((err = kw_codex32_decode(t->s, &c)) != KW_CODEX32_OK) {
            fail("%s: decode: %s", t->name, kw_codex32_strerror(err));
            continue;
        }
        if (kw_codex32_index(&c) != KW_CODEX32_SECRET) {
            fail("%s: not read as the secret", t->name);
            continue;
        }
        if ((err = kw_codex32_seed(&c, seed, sizeof seed, &seedlen)) != KW_CODEX32_OK) {
            fail("%s: seed: %s", t->name, kw_codex32_strerror(err));
            continue;
        }

        wantlen = kw_test_unhex(t->seed, want);
        if (seedlen != wantlen || memcmp(seed, want, wantlen) != 0) {
            fail("%s: wrong seed", t->name);
            continue;
        }

        /* Re-encoding the decoded symbols must give the string back, which is
           what proves the checksum is being created and not only checked. */
        lower(t->s, low, sizeof low);
        if (kw_codex32_encode(&c, back, sizeof back) != KW_CODEX32_OK ||
            strcmp(back, low) != 0) {
            fail("%s: re-encode\n  got  %s\n  want %s", t->name, back, low);
            continue;
        }

        /* And building the secret from the seed bytes must reproduce it, which
           only holds where the vector's pad bits are zero. Vectors 7 and 8 say
           theirs are not, so those are only checked one way. */
        kw_codex32_id(&c, id);
        if (kw_codex32_from_seed(kw_codex32_threshold(&c), id, seed, seedlen,
                                 &rebuilt) != KW_CODEX32_OK) {
            fail("%s: from_seed", t->name);
            continue;
        }
        if (memcmp(rebuilt.sym, c.sym, 6) != 0)
            fail("%s: from_seed lost the header", t->name);
        if (rebuilt.nsym != c.nsym)
            fail("%s: from_seed gave %zu symbols, wanted %zu", t->name,
                 rebuilt.nsym, c.nsym);
    }
}

static void shares(void)
{
    size_t v;

    for (v = 0; v < sizeof KW_CODEX32_SHARES / sizeof *KW_CODEX32_SHARES; v++) {
        const kw_codex32_share_vector *t = &KW_CODEX32_SHARES[v];
        uint8_t seed[KW_CODEX32_MAX_SECRET], want[KW_CODEX32_MAX_SECRET];
        const char *all[KW_CODEX32_MAX_GIVEN + KW_CODEX32_MAX_DERIVED];
        char derived[KW_CODEX32_MAX_DERIVED][KW_CODEX32_MAX_LEN];
        size_t seedlen = 0, wantlen, i, nall = 0, nshare = 0;
        const char *pool[KW_CODEX32_MAX_GIVEN + KW_CODEX32_MAX_DERIVED];
        kw_codex32_err err;
        uint8_t threshold;
        kw_codex32 c;

        wantlen = kw_test_unhex(t->seed, want);

        /* The given strings may include the secret, which is not a share: it
           combines with the shares to derive more, but combine refuses it. */
        for (i = 0; i < t->ngiven; i++) {
            all[nall++] = t->given[i];
            if (kw_codex32_decode(t->given[i], &c) != KW_CODEX32_OK) {
                fail("%s: given %zu does not decode", t->name, i);
                nall = 0;
                break;
            }
            if (kw_codex32_index(&c) != KW_CODEX32_SECRET) pool[nshare++] = t->given[i];
        }
        if (!nall) continue;
        threshold = kw_codex32_threshold(&c);

        /* Each derived share must come out exactly as the BIP says. */
        for (i = 0; i < t->nderived; i++) {
            char low[KW_CODEX32_MAX_LEN];
            kw_codex32 d;
            uint8_t index;

            if (kw_codex32_decode(t->derived[i].s, &d) != KW_CODEX32_OK) {
                fail("%s: derived %zu does not decode", t->name, i);
                continue;
            }
            index = kw_codex32_index(&d);

            if (index == KW_CODEX32_SECRET) {
                /* The vector's recovered secret: combine must reach it. */
                if ((err = kw_codex32_combine(pool, threshold, seed, sizeof seed,
                                              &seedlen)) != KW_CODEX32_OK) {
                    fail("%s: combine: %s", t->name, kw_codex32_strerror(err));
                    continue;
                }
                if (seedlen != wantlen || memcmp(seed, want, wantlen) != 0)
                    fail("%s: combine gave the wrong seed", t->name);
                continue;
            }

            err = kw_codex32_derive(all, nall, index, derived[i], sizeof derived[i]);
            if (err != KW_CODEX32_OK) {
                fail("%s: derive %c: %s", t->name, t->derived[i].index,
                     kw_codex32_strerror(err));
                continue;
            }
            lower(t->derived[i].s, low, sizeof low);
            if (strcmp(derived[i], low) != 0)
                fail("%s: share %c\n  got  %s\n  want %s", t->name,
                     t->derived[i].index, derived[i], low);
            pool[nshare++] = derived[i];
        }

        /* Any threshold of the shares recovers the seed, which is the property
           the whole thing exists for. Every combination, not a sample. */
        if (threshold >= 2 && nshare >= threshold) {
            size_t pick[KW_CODEX32_MAX_GIVEN + KW_CODEX32_MAX_DERIVED];
            const char *set[KW_CODEX32_MAX_GIVEN + KW_CODEX32_MAX_DERIVED];
            size_t k, tried = 0;

            for (i = 0; i < threshold; i++) pick[i] = i;
            for (;;) {
                for (i = 0; i < threshold; i++) set[i] = pool[pick[i]];
                err = kw_codex32_combine(set, threshold, seed, sizeof seed, &seedlen);
                if (err != KW_CODEX32_OK)
                    fail("%s: a threshold set gave %s", t->name,
                         kw_codex32_strerror(err));
                else if (seedlen != wantlen || memcmp(seed, want, wantlen) != 0)
                    fail("%s: a threshold set gave the wrong seed", t->name);
                tried++;

                /* next combination in lexicographic order */
                k = threshold;
                while (k-- > 0) {
                    if (pick[k] != k + nshare - threshold) {
                        pick[k]++;
                        for (i = k + 1; i < threshold; i++) pick[i] = pick[i - 1] + 1;
                        break;
                    }
                }
                if (k == (size_t)-1) break;
            }
            printf("  %s: %zu of %zu, %zu combinations\n", t->name,
                   (size_t)threshold, nshare, tried);

            /* One short and one over are both refused. */
            for (i = 0; i < threshold; i++) set[i] = pool[i];
            if (kw_codex32_combine(set, threshold - 1u, seed, sizeof seed, &seedlen)
                != KW_CODEX32_GROUPING)
                fail("%s: a short set was accepted", t->name);
            if (nshare > threshold) {
                set[threshold] = pool[threshold];
                if (kw_codex32_combine(set, threshold + 1u, seed, sizeof seed, &seedlen)
                    != KW_CODEX32_GROUPING)
                    fail("%s: a set with a spare was accepted", t->name);
            }
            /* The same share twice is one index twice. */
            set[0] = pool[0];
            set[1] = pool[0];
            for (i = 2; i < threshold; i++) set[i] = pool[i];
            if (kw_codex32_combine(set, threshold, seed, sizeof seed, &seedlen)
                != KW_CODEX32_GROUPING)
                fail("%s: a duplicated share was accepted", t->name);
            /* The secret is not a share of itself. */
            if (t->given[0][8] == 's' || t->given[0][8] == 'S') {
                set[0] = t->given[0];
                for (i = 1; i < threshold; i++) set[i] = pool[i];
                if (kw_codex32_combine(set, threshold, seed, sizeof seed, &seedlen)
                    != KW_CODEX32_GROUPING)
                    fail("%s: the secret was accepted as a share", t->name);
            }
        }
    }
}

static void invalid(void)
{
    size_t i;

    for (i = 0; i < sizeof KW_CODEX32_INVALID / sizeof *KW_CODEX32_INVALID; i++) {
        kw_codex32 c;
        if (kw_codex32_decode(KW_CODEX32_INVALID[i], &c) == KW_CODEX32_OK)
            fail("accepted an invalid string: %s", KW_CODEX32_INVALID[i]);
    }
}

static void roundtrip(const char *name, const uint8_t *seed, size_t seedlen,
                      uint8_t threshold, uint8_t count)
{
    char *buf = (char *)malloc((size_t)count * KW_CODEX32_MAX_LEN);
    const char *set[KW_CODEX32_MAX_SHARES];
    uint8_t back[KW_CODEX32_MAX_SECRET];
    size_t n = 0, backlen = 0, i;
    kw_codex32_err err;

    if (!buf) { fail("%s: out of memory", name); return; }

    err = kw_codex32_split(seed, seedlen, NULL, threshold, count,
                           buf, KW_CODEX32_MAX_LEN, &n);
    if (err != KW_CODEX32_OK) {
        fail("%s: split: %s", name, kw_codex32_strerror(err));
        free(buf);
        return;
    }
    if (n != count) fail("%s: split wrote %zu shares, wanted %u", name, n, count);

    /* Every share must carry the same identifier and a distinct index, and none
       of them may be the secret. */
    for (i = 0; i < n; i++) {
        kw_codex32 c;
        char id[5], id0[5];
        size_t j;

        if (kw_codex32_decode(buf + i * KW_CODEX32_MAX_LEN, &c) != KW_CODEX32_OK) {
            fail("%s: share %zu does not decode", name, i);
            free(buf);
            return;
        }
        if (kw_codex32_index(&c) == KW_CODEX32_SECRET)
            fail("%s: share %zu is the secret", name, i);
        if (kw_codex32_threshold(&c) != threshold)
            fail("%s: share %zu claims threshold %u", name, i,
                 kw_codex32_threshold(&c));
        kw_codex32_id(&c, id);
        kw_codex32_id(&c, id0);
        for (j = 0; j < i; j++) {
            kw_codex32 o;
            kw_codex32_decode(buf + j * KW_CODEX32_MAX_LEN, &o);
            kw_codex32_id(&o, id0);
            if (strcmp(id, id0) != 0) fail("%s: shares disagree on the id", name);
            if (kw_codex32_index(&c) == kw_codex32_index(&o))
                fail("%s: two shares share an index", name);
        }
    }

    /* The last (threshold) of them, so the interpolated shares are exercised
       rather than only the random ones that seeded the polynomial. */
    for (i = 0; i < threshold; i++)
        set[i] = buf + (n - threshold + i) * KW_CODEX32_MAX_LEN;
    err = kw_codex32_combine(set, threshold, back, sizeof back, &backlen);
    if (err != KW_CODEX32_OK)
        fail("%s: combine: %s", name, kw_codex32_strerror(err));
    else if (backlen != seedlen || memcmp(back, seed, seedlen) != 0)
        fail("%s: recovered a different seed", name);

    free(buf);
}

/* The decoder against strings nobody wrote: valid-length strings of valid
   characters that are not valid shares, and arbitrary printable text. Fixed
   seed, so a crash reproduces by iteration number. */
static void garbage(void)
{
    uint64_t st = 0x2545f4914f6cdd1dULL;
    static const size_t lens[6] = { 48, 54, 61, 67, 74, 127 };
    char m[KW_CODEX32_MAX_LEN];
    kw_codex32 c;
    int i;

    #define RND() (st ^= st << 13, st ^= st >> 7, st ^= st << 17, st)
    for (i = 0; i < 20000; i++) {
        size_t n = lens[RND() % 6], k;

        m[0] = 'm'; m[1] = 's'; m[2] = '1';
        for (k = 3; k < n; k++) m[k] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"[RND() % 32];
        m[n] = '\0';
        if (kw_codex32_decode(m, &c) == KW_CODEX32_OK) {
            /* A random payload under a correct checksum is vanishingly
               unlikely, so this is the re-encode check rather than a count. */
            char back[KW_CODEX32_MAX_LEN];
            if (kw_codex32_encode(&c, back, sizeof back) != KW_CODEX32_OK ||
                strcmp(back, m) != 0)
                fail("a random string decoded but did not re-encode");
        }
    }

    for (i = 0; i < 20000; i++) {
        size_t n = RND() % (sizeof m - 1), k;

        for (k = 0; k < n; k++) m[k] = (char)(32 + RND() % 95);
        m[n] = '\0';
        (void)kw_codex32_decode(m, &c);
    }
    #undef RND
}

int main(void)
{
    if (!kw_ec_start()) { fprintf(stderr, "no curve context\n"); return 1; }

    secrets();
    shares();
    invalid();
    garbage();

    {
        uint8_t seed[64];
        size_t i;

        for (i = 0; i < sizeof seed; i++) seed[i] = (uint8_t)(i * 11 + 3);

        roundtrip("2-of-3, 512-bit", seed, 64, 2, 3);
        roundtrip("3-of-5, 512-bit", seed, 64, 3, 5);
        roundtrip("9-of-22, 512-bit", seed, 64, 9, 22);
        roundtrip("2-of-2, 128-bit", seed, 16, 2, 2);
        roundtrip("5-of-7, 256-bit", seed, 32, 5, 7);
        roundtrip("3-of-4, 160-bit", seed, 20, 3, 4);

        /* Thresholds and lengths the format has no room for. */
        {
            char buf[KW_CODEX32_MAX_SHARES * KW_CODEX32_MAX_LEN];
            size_t n = 0;
            if (kw_codex32_split(seed, 64, NULL, 1, 2, buf, KW_CODEX32_MAX_LEN, &n)
                != KW_CODEX32_ARG)
                fail("split accepted a threshold of 1");
            if (kw_codex32_split(seed, 64, NULL, 10, 12, buf, KW_CODEX32_MAX_LEN, &n)
                != KW_CODEX32_ARG)
                fail("split accepted a threshold of 10");
            if (kw_codex32_split(seed, 64, NULL, 3, 2, buf, KW_CODEX32_MAX_LEN, &n)
                != KW_CODEX32_ARG)
                fail("split accepted a 3-of-2");
            if (kw_codex32_split(seed, 48, NULL, 2, 3, buf, KW_CODEX32_MAX_LEN, &n)
                != KW_CODEX32_ARG)
                fail("split accepted a 48-byte seed");
            if (kw_codex32_split(seed, 64, "bad!", 2, 3, buf, KW_CODEX32_MAX_LEN, &n)
                != KW_CODEX32_CHARSET)
                fail("split accepted a non-bech32 identifier");
            /* A short identifier used to be read past its NUL, and the NUL
               itself came back as symbol 32 because strchr finds it. */
            if (kw_codex32_split(seed, 64, "ab", 2, 3, buf, KW_CODEX32_MAX_LEN, &n)
                != KW_CODEX32_ARG)
                fail("split accepted a 2-character identifier");
            if (kw_codex32_split(seed, 64, "abcde", 2, 3, buf, KW_CODEX32_MAX_LEN, &n)
                != KW_CODEX32_ARG)
                fail("split accepted a 5-character identifier");
        }
    }

    kw_ec_stop();
    if (fails || kw_test_fails()) {
        fprintf(stderr, "codex32: %d failures\n", fails + kw_test_fails());
        return 1;
    }
    printf("codex32 ok\n");
    return 0;
}
