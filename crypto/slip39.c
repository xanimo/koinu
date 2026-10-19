/* koinu.dog - SLIP-39 Shamir backup of the BIP32 master seed
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "slip39.h"

#include <stdlib.h>
#include <string.h>

#include "hmac.h"
#include "mem.h"
#include "pbkdf2.h"
#include "rng.h"
#include "sha2.h"
#include "wordlist_slip39.h"

#define DIGEST_LEN   4
#define DIGEST_INDEX 254
#define SECRET_INDEX 255
#define HALF_MAX     (KW_SLIP39_MAX_SECRET / 2)
/* A threshold's worth of shares plus the digest and the secret. */
#define MAX_POINTS   (KW_SLIP39_MAX_SHARES + 2)
#define HEADER_WORDS 4
#define CHECK_WORDS  3

const char *kw_slip39_strerror(kw_slip39_err e)
{
    switch (e) {
    case KW_SLIP39_OK:       return "ok";
    case KW_SLIP39_ARG:      return "parameter out of range";
    case KW_SLIP39_WORD:     return "word is not in the SLIP-39 list";
    case KW_SLIP39_LENGTH:   return "wrong number of words";
    case KW_SLIP39_CHECKSUM: return "checksum failed";
    case KW_SLIP39_PADDING:  return "share padding is wrong";
    case KW_SLIP39_GROUPING: return "shares do not form one threshold set";
    case KW_SLIP39_DIGEST:   return "reconstructed secret failed its digest";
    case KW_SLIP39_RNG:      return "no entropy";
    }
    return "unknown error";
}

/* GF(256) with the AES field polynomial and x+1 as the generator, which is
   what the spec's reference tables are. Built per call rather than kept in a
   static, so nothing has to guard an initialisation. */
typedef struct {
    uint8_t exp[255];
    uint8_t log[256];
} gf_tables;

static void gf_init(gf_tables *t)
{
    unsigned poly = 1;
    int i;

    memset(t->log, 0, sizeof t->log);
    for (i = 0; i < 255; i++) {
        t->exp[i] = (uint8_t)poly;
        t->log[poly] = (uint8_t)i;
        poly = (poly << 1) ^ poly;           /* times x + 1 */
        if (poly & 0x100) poly ^= 0x11b;     /* mod x^8 + x^4 + x^3 + x + 1 */
    }
}

/* Lagrange interpolation at (x) of the m points (xs[i], ys[i]), each y being n
   bytes evaluated independently. The x values must be distinct; every caller
   here checks that first. */
static void interpolate(const gf_tables *t, const uint8_t *xs,
                        const uint8_t *const *ys, size_t m, size_t n,
                        uint8_t x, uint8_t *out)
{
    int log_prod = 0;
    size_t i, j, k;

    for (i = 0; i < m; i++) {
        if (xs[i] == x) { memcpy(out, ys[i], n); return; }
        log_prod += t->log[xs[i] ^ x];
    }

    memset(out, 0, n);
    for (i = 0; i < m; i++) {
        int eval = log_prod - t->log[xs[i] ^ x];
        for (j = 0; j < m; j++) eval -= t->log[xs[i] ^ xs[j]];
        eval = ((eval % 255) + 255) % 255;
        for (k = 0; k < n; k++) {
            if (ys[i][k]) out[k] ^= t->exp[(t->log[ys[i][k]] + eval) % 255];
        }
    }
}

static void digest_make(const uint8_t *r, size_t rlen,
                        const uint8_t *s, size_t slen,
                        uint8_t out[DIGEST_LEN])
{
    uint8_t mac[KW_SHA256_LEN];

    kw_hmac_sha256(r, rlen, s, slen, mac);
    memcpy(out, mac, DIGEST_LEN);
    kw_secure_zero(mac, sizeof mac);
}

static int distinct(const uint8_t *v, size_t n)
{
    size_t i, j;

    for (i = 0; i < n; i++)
        for (j = i + 1; j < n; j++)
            if (v[i] == v[j]) return 0;
    return 1;
}

static kw_slip39_err split_secret(const gf_tables *t, uint8_t threshold, uint8_t count,
                                  const uint8_t *secret, size_t n,
                                  uint8_t shares[KW_SLIP39_MAX_SHARES][KW_SLIP39_MAX_SECRET])
{
    uint8_t digest_share[KW_SLIP39_MAX_SECRET];
    const uint8_t *ys[MAX_POINTS];
    uint8_t xs[MAX_POINTS];
    kw_slip39_err err = KW_SLIP39_OK;
    uint8_t nrand, i;
    size_t m = 0;

    if (threshold == 0 || threshold > count || count > KW_SLIP39_MAX_SHARES)
        return KW_SLIP39_ARG;
    if (n < KW_SLIP39_MIN_SECRET || n > KW_SLIP39_MAX_SECRET || (n % 2))
        return KW_SLIP39_ARG;

    if (threshold == 1) {
        for (i = 0; i < count; i++) memcpy(shares[i], secret, n);
        return KW_SLIP39_OK;
    }

    /* The first threshold - 2 shares are random, and the digest share and the
       secret itself make up the threshold. Every remaining share is then the
       polynomial those points determine, evaluated at its own index. */
    nrand = (uint8_t)(threshold - 2);
    for (i = 0; i < nrand; i++) {
        if (!kw_random_bytes(shares[i], n)) { err = KW_SLIP39_RNG; goto out; }
        xs[m] = i;
        ys[m] = shares[i];
        m++;
    }

    if (!kw_random_bytes(digest_share + DIGEST_LEN, n - DIGEST_LEN)) {
        err = KW_SLIP39_RNG;
        goto out;
    }
    digest_make(digest_share + DIGEST_LEN, n - DIGEST_LEN, secret, n, digest_share);
    xs[m] = DIGEST_INDEX;
    ys[m] = digest_share;
    m++;
    xs[m] = SECRET_INDEX;
    ys[m] = secret;
    m++;

    for (i = nrand; i < count; i++) interpolate(t, xs, ys, m, n, i, shares[i]);

out:
    kw_secure_zero(digest_share, sizeof digest_share);
    return err;
}

static kw_slip39_err recover_secret(const gf_tables *t, uint8_t threshold,
                                    const uint8_t *xs, const uint8_t *const *ys,
                                    size_t m, size_t n, uint8_t *out)
{
    uint8_t d[KW_SLIP39_MAX_SECRET], want[DIGEST_LEN];
    kw_slip39_err err = KW_SLIP39_OK;

    if (m != threshold) return KW_SLIP39_GROUPING;
    if (!distinct(xs, m)) return KW_SLIP39_GROUPING;

    if (threshold == 1) {
        memcpy(out, ys[0], n);
        return KW_SLIP39_OK;
    }

    interpolate(t, xs, ys, m, n, SECRET_INDEX, out);
    interpolate(t, xs, ys, m, n, DIGEST_INDEX, d);
    digest_make(d + DIGEST_LEN, n - DIGEST_LEN, out, n, want);
    if (kw_memcmp_ct(want, d, DIGEST_LEN) != 0) {
        kw_secure_zero(out, n);
        err = KW_SLIP39_DIGEST;
    }

    kw_secure_zero(d, sizeof d);
    kw_secure_zero(want, sizeof want);
    return err;
}

static int pass_ok(const char *p, size_t *len)
{
    size_t i;

    if (!p) return 0;
    for (i = 0; p[i]; i++) {
        if (i == KW_SLIP39_PASS_MAX) return 0;
        if ((unsigned char)p[i] < 32 || (unsigned char)p[i] > 126) return 0;
    }
    *len = i;
    return 1;
}

static int round_f(uint8_t i, const char *pass, size_t passlen, uint32_t iterations,
                   uint16_t id, uint8_t ext, const uint8_t *r, size_t half,
                   uint8_t *out)
{
    uint8_t password[1 + KW_SLIP39_PASS_MAX];
    uint8_t salt[8 + HALF_MAX];
    size_t slen = 0;
    int ok;

    password[0] = i;
    memcpy(password + 1, pass, passlen);

    /* An extendable backup salts with nothing, so the same shares can be
       reissued under a fresh id. */
    if (!ext) {
        memcpy(salt, "shamir", 6);
        salt[6] = (uint8_t)(id >> 8);
        salt[7] = (uint8_t)(id & 0xff);
        slen = 8;
    }
    memcpy(salt + slen, r, half);
    slen += half;

    ok = kw_pbkdf2_hmac_sha256(password, 1 + passlen, salt, slen, iterations, out, half);

    kw_secure_zero(password, sizeof password);
    kw_secure_zero(salt, sizeof salt);
    return ok;
}

/* Four-round Feistel network over the two halves of the secret, which is its
   own inverse once the round order is reversed. */
static int feistel(const uint8_t *in, size_t n, const char *pass, size_t passlen,
                   uint8_t e, uint16_t id, uint8_t ext, int decrypt, uint8_t *out)
{
    uint8_t l[HALF_MAX], r[HALF_MAX], f[HALF_MAX], prev[HALF_MAX];
    uint32_t iterations = 2500u << e;
    size_t half = n / 2, j;
    int ok = 1, k;

    memcpy(l, in, half);
    memcpy(r, in + half, half);

    for (k = 0; k < 4; k++) {
        uint8_t i = (uint8_t)(decrypt ? 3 - k : k);
        if (!round_f(i, pass, passlen, iterations, id, ext, r, half, f)) { ok = 0; break; }
        memcpy(prev, r, half);
        for (j = 0; j < half; j++) r[j] = l[j] ^ f[j];
        memcpy(l, prev, half);
    }

    if (ok) {
        memcpy(out, r, half);
        memcpy(out + half, l, half);
    }

    kw_secure_zero(l, sizeof l);
    kw_secure_zero(r, sizeof r);
    kw_secure_zero(f, sizeof f);
    kw_secure_zero(prev, sizeof prev);
    return ok;
}

/* RS1024 over GF(1024): the data words prefixed by the customization string's
   bytes, three words of checksum, and a residue of 1. */
static uint32_t rs1024_polymod(const uint16_t *v, size_t n)
{
    static const uint32_t GEN[10] = {
        0x00e0e040, 0x01c1c080, 0x03838100, 0x07070200, 0x0e0e0009,
        0x1c0c2412, 0x38086c24, 0x3090fc48, 0x21b1f890, 0x03f3f120
    };
    uint32_t chk = 1;
    size_t i;
    int j;

    for (i = 0; i < n; i++) {
        uint32_t b = chk >> 20;
        chk = ((chk & 0xfffff) << 10) ^ v[i];
        for (j = 0; j < 10; j++)
            if ((b >> j) & 1) chk ^= GEN[j];
    }
    return chk;
}

static size_t rs1024_prefix(uint8_t ext, uint16_t *out)
{
    const char *cs = ext ? "shamir_extendable" : "shamir";
    size_t i, n = strlen(cs);

    for (i = 0; i < n; i++) out[i] = (uint8_t)cs[i];
    return n;
}

/* Words of the customization string followed by the mnemonic's words; checksum
   words included when verifying, zeroed when creating. */
static size_t rs1024_values(uint8_t ext, const uint16_t *w, size_t nw, uint16_t *out)
{
    size_t n = rs1024_prefix(ext, out);

    memcpy(out + n, w, nw * sizeof *w);
    return n + nw;
}

static int rs1024_verify(uint8_t ext, const uint16_t *w, size_t nw)
{
    uint16_t v[17 + KW_SLIP39_MAX_WORDS];
    size_t n = rs1024_values(ext, w, nw, v);

    return rs1024_polymod(v, n) == 1;
}

static void rs1024_create(uint8_t ext, const uint16_t *w, size_t nw, uint16_t *out)
{
    uint16_t v[17 + KW_SLIP39_MAX_WORDS + CHECK_WORDS];
    size_t n = rs1024_values(ext, w, nw, v);
    uint32_t pm;
    int i;

    for (i = 0; i < CHECK_WORDS; i++) v[n + i] = 0;
    pm = rs1024_polymod(v, n + CHECK_WORDS) ^ 1;
    for (i = 0; i < CHECK_WORDS; i++) out[i] = (uint16_t)((pm >> (10 * (2 - i))) & 1023);
}

/* The list is alphabetical and no word is a prefix of another, so a word that
   stops short of a candidate sorts before it. */
static int word_index(const char *w, size_t len)
{
    size_t lo = 0, hi = 1024;

    if (len == 0) return -1;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        const char *cand = KW_SLIP39_WORDLIST[mid];
        int c = strncmp(w, cand, len);
        if (c == 0 && cand[len]) c = -1;
        if (c == 0) return (int)mid;
        if (c < 0) hi = mid; else lo = mid + 1;
    }
    return -1;
}

static int is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static kw_slip39_err to_words(const char *mnemonic, uint16_t *w, size_t *nw)
{
    const char *p = mnemonic;
    size_t n = 0;

    while (*p) {
        const char *s;
        int k;

        while (is_space(*p)) p++;
        if (!*p) break;
        s = p;
        while (*p && !is_space(*p)) p++;
        if (n == KW_SLIP39_MAX_WORDS) return KW_SLIP39_LENGTH;
        k = word_index(s, (size_t)(p - s));
        if (k < 0) return KW_SLIP39_WORD;
        w[n++] = (uint16_t)k;
    }

    *nw = n;
    return KW_SLIP39_OK;
}

/* Words to the share value's byte count, or 0 if the word count cannot name
   one. The padding is what rounds 8n bits up to a multiple of 10, so it is the
   padded length modulo 16 and the spec caps it at a byte. */
static size_t value_bytes(size_t nw)
{
    size_t padded, padding;

    if (nw < KW_SLIP39_MIN_WORDS || nw > KW_SLIP39_MAX_WORDS) return 0;
    padded = (nw - HEADER_WORDS - CHECK_WORDS) * 10;
    padding = padded % 16;
    if (padding > 8) return 0;
    if (padded - padding < KW_SLIP39_MIN_SECRET * 8) return 0;
    return (padded - padding) / 8;
}

kw_slip39_err kw_slip39_decode(const char *mnemonic, kw_slip39_share *out)
{
    uint16_t w[KW_SLIP39_MAX_WORDS];
    size_t nw = 0, n, padding, bit, k;
    uint64_t hdr;
    uint8_t ext;
    kw_slip39_err err;
    int b;

    if (!mnemonic || !out) return KW_SLIP39_ARG;
    if ((err = to_words(mnemonic, w, &nw)) != KW_SLIP39_OK) return err;

    n = value_bytes(nw);
    if (n == 0 || n > KW_SLIP39_MAX_SECRET) return KW_SLIP39_LENGTH;

    hdr = ((uint64_t)w[0] << 30) | ((uint64_t)w[1] << 20) |
          ((uint64_t)w[2] << 10) | (uint64_t)w[3];
    ext = (uint8_t)((hdr >> 24) & 1);

    /* The flag that picks the customization string is itself under the
       checksum, so it is read before the checksum can be checked. */
    if (!rs1024_verify(ext, w, nw)) return KW_SLIP39_CHECKSUM;

    memset(out, 0, sizeof *out);
    out->id               = (uint16_t)((hdr >> 25) & 0x7fff);
    out->ext              = ext;
    out->e                = (uint8_t)((hdr >> 20) & 0xf);
    out->group_index      = (uint8_t)((hdr >> 16) & 0xf);
    out->group_threshold  = (uint8_t)(((hdr >> 12) & 0xf) + 1);
    out->group_count      = (uint8_t)(((hdr >> 8) & 0xf) + 1);
    out->member_index     = (uint8_t)((hdr >> 4) & 0xf);
    out->member_threshold = (uint8_t)((hdr & 0xf) + 1);
    out->valuelen         = n;

    padding = (nw - HEADER_WORDS - CHECK_WORDS) * 10 - n * 8;
    if (padding && (w[HEADER_WORDS] >> (10 - padding))) return KW_SLIP39_PADDING;

    for (k = 0, bit = padding; k < n; k++) {
        unsigned byte = 0;
        for (b = 0; b < 8; b++, bit++) {
            unsigned word = w[HEADER_WORDS + bit / 10];
            byte = (byte << 1) | ((word >> (9 - bit % 10)) & 1);
        }
        out->value[k] = (uint8_t)byte;
    }

    return KW_SLIP39_OK;
}

kw_slip39_err kw_slip39_encode(const kw_slip39_share *s, char *out, size_t outcap)
{
    uint16_t w[KW_SLIP39_MAX_WORDS];
    size_t nw, vwords, padding, bit, k, used = 0;
    uint64_t hdr;
    int b;

    if (!s || !out) return KW_SLIP39_ARG;
    if (s->valuelen < KW_SLIP39_MIN_SECRET || s->valuelen > KW_SLIP39_MAX_SECRET ||
        (s->valuelen % 2))
        return KW_SLIP39_ARG;
    if (s->id > 0x7fff || s->ext > 1 || s->e > 15) return KW_SLIP39_ARG;
    if (s->group_index > 15 || s->member_index > 15) return KW_SLIP39_ARG;
    if (s->group_threshold == 0 || s->group_threshold > 16 ||
        s->group_count == 0 || s->group_count > 16 ||
        s->member_threshold == 0 || s->member_threshold > 16)
        return KW_SLIP39_ARG;

    vwords = (s->valuelen * 8 + 9) / 10;
    padding = vwords * 10 - s->valuelen * 8;
    nw = HEADER_WORDS + vwords + CHECK_WORDS;

    hdr = ((uint64_t)s->id << 25) | ((uint64_t)s->ext << 24) | ((uint64_t)s->e << 20) |
          ((uint64_t)s->group_index << 16) |
          ((uint64_t)(s->group_threshold - 1) << 12) |
          ((uint64_t)(s->group_count - 1) << 8) |
          ((uint64_t)s->member_index << 4) |
          (uint64_t)(s->member_threshold - 1);

    w[0] = (uint16_t)((hdr >> 30) & 1023);
    w[1] = (uint16_t)((hdr >> 20) & 1023);
    w[2] = (uint16_t)((hdr >> 10) & 1023);
    w[3] = (uint16_t)(hdr & 1023);

    for (k = 0; k < vwords; k++) w[HEADER_WORDS + k] = 0;
    for (k = 0, bit = padding; k < s->valuelen; k++) {
        for (b = 7; b >= 0; b--, bit++) {
            unsigned v = (s->value[k] >> b) & 1;
            w[HEADER_WORDS + bit / 10] |= (uint16_t)(v << (9 - bit % 10));
        }
    }

    rs1024_create(s->ext, w, HEADER_WORDS + vwords, w + HEADER_WORDS + vwords);

    for (k = 0; k < nw; k++) {
        const char *word = KW_SLIP39_WORDLIST[w[k]];
        size_t len = strlen(word);
        if (used + len + (k ? 1 : 0) + 1 > outcap) return KW_SLIP39_ARG;
        if (k) out[used++] = ' ';
        memcpy(out + used, word, len);
        used += len;
    }
    out[used] = '\0';
    return KW_SLIP39_OK;
}

kw_slip39_err kw_slip39_split(const uint8_t *ms, size_t mslen,
                              const char *passphrase, uint8_t e,
                              uint8_t group_threshold,
                              const kw_slip39_group *groups, size_t ngroups,
                              char *out, size_t stride, size_t *nout)
{
    uint8_t gshare[KW_SLIP39_MAX_SHARES][KW_SLIP39_MAX_SECRET];
    uint8_t mshare[KW_SLIP39_MAX_SHARES][KW_SLIP39_MAX_SECRET];
    uint8_t ems[KW_SLIP39_MAX_SECRET];
    uint8_t idbytes[2];
    gf_tables t;
    kw_slip39_err err = KW_SLIP39_OK;
    size_t passlen, g, i, written = 0;
    uint16_t id;

    if (!ms || !groups || !out || !nout) return KW_SLIP39_ARG;
    if (stride < KW_SLIP39_MNEMONIC_MAX) return KW_SLIP39_ARG;
    if (mslen < KW_SLIP39_MIN_SECRET || mslen > KW_SLIP39_MAX_SECRET || (mslen % 2))
        return KW_SLIP39_ARG;
    if (e > 15) return KW_SLIP39_ARG;
    if (ngroups == 0 || ngroups > KW_SLIP39_MAX_GROUPS) return KW_SLIP39_ARG;
    if (group_threshold == 0 || group_threshold > ngroups) return KW_SLIP39_ARG;
    if (!pass_ok(passphrase, &passlen)) return KW_SLIP39_ARG;

    /* A member threshold of one over several shares hands out copies of the same
       share while naming a threshold, which is the spec's own refusal. A group
       threshold of one over several groups is not the same thing: every group
       receives the same group share and then splits it differently, so
       "my share, or two of the family's" is a real layout and the one people
       usually mean. */
    for (g = 0; g < ngroups; g++) {
        if (groups[g].count == 0 || groups[g].count > KW_SLIP39_MAX_SHARES)
            return KW_SLIP39_ARG;
        if (groups[g].threshold == 0 || groups[g].threshold > groups[g].count)
            return KW_SLIP39_ARG;
        if (groups[g].threshold == 1 && groups[g].count > 1) return KW_SLIP39_ARG;
    }

    if (!kw_random_bytes(idbytes, sizeof idbytes)) return KW_SLIP39_RNG;
    id = (uint16_t)((((uint16_t)idbytes[0] << 8) | idbytes[1]) & 0x7fff);

    gf_init(&t);
    kw_secure_keep(gshare, sizeof gshare);
    kw_secure_keep(mshare, sizeof mshare);
    kw_secure_keep(ems, sizeof ems);

    if (!feistel(ms, mslen, passphrase, passlen, e, id, 1, 0, ems)) {
        err = KW_SLIP39_ARG;
        goto out;
    }
    if ((err = split_secret(&t, group_threshold, (uint8_t)ngroups, ems, mslen, gshare))
        != KW_SLIP39_OK)
        goto out;

    for (g = 0; g < ngroups; g++) {
        if ((err = split_secret(&t, groups[g].threshold, groups[g].count,
                                gshare[g], mslen, mshare)) != KW_SLIP39_OK)
            goto out;

        for (i = 0; i < groups[g].count; i++) {
            kw_slip39_share s;

            memset(&s, 0, sizeof s);
            s.id               = id;
            s.ext              = 1;
            s.e                = e;
            s.group_index      = (uint8_t)g;
            s.group_threshold  = group_threshold;
            s.group_count      = (uint8_t)ngroups;
            s.member_index     = (uint8_t)i;
            s.member_threshold = groups[g].threshold;
            s.valuelen         = mslen;
            memcpy(s.value, mshare[i], mslen);

            err = kw_slip39_encode(&s, out + written * stride, stride);
            kw_secure_zero(&s, sizeof s);
            if (err != KW_SLIP39_OK) goto out;
            written++;
        }
    }

    *nout = written;

out:
    kw_secure_zero(ems, sizeof ems);
    kw_secure_zero(gshare, sizeof gshare);
    kw_secure_zero(mshare, sizeof mshare);
    kw_secure_forget(ems, sizeof ems);
    kw_secure_forget(mshare, sizeof mshare);
    kw_secure_forget(gshare, sizeof gshare);
    if (err != KW_SLIP39_OK) {
        for (i = 0; i < written; i++) kw_secure_zero(out + i * stride, stride);
        *nout = 0;
    }
    return err;
}

kw_slip39_err kw_slip39_combine(const char *const *mnemonics, size_t nm,
                                const char *passphrase,
                                uint8_t *out, size_t outcap, size_t *outlen)
{
    uint8_t gshare[KW_SLIP39_MAX_GROUPS][KW_SLIP39_MAX_SECRET];
    uint8_t gx[KW_SLIP39_MAX_GROUPS];
    const uint8_t *gy[KW_SLIP39_MAX_GROUPS];
    uint8_t ems[KW_SLIP39_MAX_SECRET];
    kw_slip39_share *sh = NULL;
    gf_tables t;
    kw_slip39_err err = KW_SLIP39_OK;
    size_t passlen, i, j, ngroups = 0, n;

    if (!mnemonics || !out || !outlen) return KW_SLIP39_ARG;
    if (nm == 0 || nm > KW_SLIP39_MAX_TOTAL) return KW_SLIP39_ARG;
    if (!pass_ok(passphrase, &passlen)) return KW_SLIP39_ARG;

    sh = malloc(nm * sizeof *sh);
    if (!sh) return KW_SLIP39_ARG;
    kw_secure_keep(sh, nm * sizeof *sh);

    for (i = 0; i < nm; i++) {
        if ((err = kw_slip39_decode(mnemonics[i], &sh[i])) != KW_SLIP39_OK) goto out;
        if (sh[i].id != sh[0].id || sh[i].ext != sh[0].ext || sh[i].e != sh[0].e ||
            sh[i].group_threshold != sh[0].group_threshold ||
            sh[i].group_count != sh[0].group_count ||
            sh[i].valuelen != sh[0].valuelen) {
            err = KW_SLIP39_GROUPING;
            goto out;
        }
        if (sh[i].group_index >= sh[i].group_count) { err = KW_SLIP39_GROUPING; goto out; }
    }

    n = sh[0].valuelen;
    if (sh[0].group_count < sh[0].group_threshold) { err = KW_SLIP39_GROUPING; goto out; }
    if (n > outcap) { err = KW_SLIP39_ARG; goto out; }

    gf_init(&t);
    kw_secure_keep(gshare, sizeof gshare);
    kw_secure_keep(ems, sizeof ems);

    /* One pass per distinct group index, in order of first appearance. Each
       group must contribute exactly its member threshold and no more, so a set
       that is one share short and a set with a spare are both refused. */
    for (i = 0; i < nm; i++) {
        uint8_t xs[KW_SLIP39_MAX_SHARES];
        const uint8_t *ys[KW_SLIP39_MAX_SHARES];
        size_t m = 0;
        int seen = 0;

        for (j = 0; j < ngroups; j++) if (gx[j] == sh[i].group_index) seen = 1;
        if (seen) continue;

        if (ngroups == KW_SLIP39_MAX_GROUPS) { err = KW_SLIP39_GROUPING; goto out; }

        for (j = 0; j < nm; j++) {
            if (sh[j].group_index != sh[i].group_index) continue;
            if (sh[j].member_threshold != sh[i].member_threshold) {
                err = KW_SLIP39_GROUPING;
                goto out;
            }
            if (m == KW_SLIP39_MAX_SHARES) { err = KW_SLIP39_GROUPING; goto out; }
            xs[m] = sh[j].member_index;
            ys[m] = sh[j].value;
            m++;
        }

        if ((err = recover_secret(&t, sh[i].member_threshold, xs, ys, m, n,
                                  gshare[ngroups])) != KW_SLIP39_OK)
            goto out;

        gx[ngroups] = sh[i].group_index;
        gy[ngroups] = gshare[ngroups];
        ngroups++;
    }

    if (ngroups != sh[0].group_threshold) { err = KW_SLIP39_GROUPING; goto out; }

    if ((err = recover_secret(&t, sh[0].group_threshold, gx, gy, ngroups, n, ems))
        != KW_SLIP39_OK)
        goto out;

    if (!feistel(ems, n, passphrase, passlen, sh[0].e, sh[0].id, sh[0].ext, 1, out)) {
        err = KW_SLIP39_ARG;
        goto out;
    }
    *outlen = n;

out:
    kw_secure_zero(ems, sizeof ems);
    kw_secure_zero(gshare, sizeof gshare);
    kw_secure_forget(ems, sizeof ems);
    kw_secure_forget(gshare, sizeof gshare);
    if (sh) {
        kw_secure_zero(sh, nm * sizeof *sh);
        kw_secure_forget(sh, nm * sizeof *sh);
        free(sh);
    }
    if (err != KW_SLIP39_OK) {
        kw_secure_zero(out, outcap);
        *outlen = 0;
    }
    return err;
}
