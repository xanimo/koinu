/* koinu.dog - codex32 (BIP-93) shares of the BIP32 master seed
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "codex32.h"

#include <string.h>

#include "mem.h"
#include "rng.h"

#define HEADER_SYM 6                      /* threshold, 4 of identifier, index */
#define CHECK_SHORT 13
#define CHECK_LONG  15
/* bech32_hrp_expand("ms") contributes five values to the codeword. */
#define HRP_EXPANDED 5

static const char CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/* The six string lengths BIP-93 allows for a master seed, which fix the seed
   length: 16, 20, 24, 28, 32 and 64 bytes. */
static const size_t VALID_LENGTHS[6] = { 48, 54, 61, 67, 74, 127 };

/* The spec's recommended share indices: bech32 letters in alphabetical order,
   with "s" left for the secret. */
static const char SHARE_LETTERS[] = "acdefghjklmnpqrtuvwxyz";

const char *kw_codex32_strerror(kw_codex32_err e)
{
    switch (e) {
    case KW_CODEX32_OK:       return "ok";
    case KW_CODEX32_ARG:      return "parameter out of range";
    case KW_CODEX32_CHARSET:  return "not a bech32 character, or the case is mixed";
    case KW_CODEX32_LENGTH:   return "not a length BIP-93 allows";
    case KW_CODEX32_PREFIX:   return "missing the ms1 prefix, or a bad threshold";
    case KW_CODEX32_CHECKSUM: return "checksum failed";
    case KW_CODEX32_GROUPING: return "shares do not form one threshold set";
    case KW_CODEX32_RNG:      return "no entropy";
    }
    return "unknown error";
}

/* The residue is 68 bits for the regular code and 79 for the long one, so it
   does not fit a uint64_t and __int128 is not there on the 32-bit build. Two
   words, with the shifts written out. */
typedef struct { uint64_t hi, lo; } res128;

static res128 polymod_short(const uint8_t *v, size_t n)
{
    static const res128 GEN[5] = {
        { 0x1ULL, 0x9dc500ce73fde210ULL },
        { 0x1ULL, 0xbfae00def77fe529ULL },
        { 0x1ULL, 0xfbd920fffe7bee52ULL },
        { 0x1ULL, 0x739640bdeee3fdadULL },
        { 0x0ULL, 0x7729a039cfc75f5aULL }
    };
    res128 r = { 0, 0x23181b3ULL };
    size_t i;
    int j;

    for (i = 0; i < n; i++) {
        unsigned b = (unsigned)(((r.lo >> 60) | (r.hi << 4)) & 31);
        uint64_t lo = r.lo & 0x0fffffffffffffffULL;        /* keep 60 bits */
        r.hi = lo >> 59;
        r.lo = (lo << 5) ^ v[i];
        for (j = 0; j < 5; j++)
            if ((b >> j) & 1) { r.hi ^= GEN[j].hi; r.lo ^= GEN[j].lo; }
    }
    return r;
}

static res128 polymod_long(const uint8_t *v, size_t n)
{
    static const res128 GEN[5] = {
        { 0x3d5ULL, 0x9d273535ea62d897ULL },
        { 0x7a9ULL, 0xbecb6361c6c51507ULL },
        { 0x543ULL, 0xf9b7e6c38d8a2a0eULL },
        { 0x0c5ULL, 0x77eaeccf1990d13cULL },
        { 0x188ULL, 0x7f74f8dc71b10651ULL }
    };
    res128 r = { 0, 0x23181b3ULL };
    size_t i;
    int j;

    for (i = 0; i < n; i++) {
        unsigned b = (unsigned)((r.hi >> 6) & 31);
        uint64_t hi = r.hi & 0x3fULL;                      /* keep 70 bits */
        r.hi = (hi << 5) | (r.lo >> 59);
        r.lo = (r.lo << 5) ^ v[i];
        for (j = 0; j < 5; j++)
            if ((b >> j) & 1) { r.hi ^= GEN[j].hi; r.lo ^= GEN[j].lo; }
    }
    return r;
}

/* Which checksum a data part of (ndata) symbols carries, counting the checksum
   itself. 94 and 95 are never legal, and the caller's length check has already
   refused them. */
static int is_long(size_t ndata)
{
    return HRP_EXPANDED + ndata >= 96;
}

static int verify_checksum(const uint8_t *data, size_t ndata)
{
    res128 r;

    if (is_long(ndata)) {
        if (HRP_EXPANDED + ndata > 1023) return 0;
        r = polymod_long(data, ndata);
        return r.hi == 0x433ULL && r.lo == 0x81e570bf4798ab26ULL;
    }
    if (HRP_EXPANDED + ndata > 93) return 0;
    r = polymod_short(data, ndata);
    return r.hi == 0x1ULL && r.lo == 0x0ce0795c2fd1e62aULL;
}

/* Append the checksum variant a data part of (nsym) symbols requires, writing
   it at data + nsym. Returns its length. */
static size_t create_checksum(uint8_t *data, size_t nsym)
{
    size_t nck = (HRP_EXPANDED + nsym + CHECK_SHORT > 93) ? CHECK_LONG : CHECK_SHORT;
    res128 r;
    size_t i;

    memset(data + nsym, 0, nck);
    if (nck == CHECK_LONG) {
        r = polymod_long(data, nsym + nck);
        r.hi ^= 0x433ULL;
        r.lo ^= 0x81e570bf4798ab26ULL;
    } else {
        r = polymod_short(data, nsym + nck);
        r.hi ^= 0x1ULL;
        r.lo ^= 0x0ce0795c2fd1e62aULL;
    }

    /* The residue's low 5*nck bits, most significant symbol first. */
    for (i = 0; i < nck; i++) {
        unsigned shift = (unsigned)(5 * (nck - 1 - i));
        uint64_t v;
        if (shift >= 64) v = r.hi >> (shift - 64);
        else v = (r.lo >> shift) | (shift ? (r.hi << (64 - shift)) : 0);
        data[nsym + i] = (uint8_t)(v & 31);
    }
    return nck;
}

/* GF(32) with x^5 + x^3 + 1, which is what BIP-93's bech32_mul is.
 *
 * Branchless and without a table, because both operands are secret here: the
 * Lagrange weights multiply share symbols, so a branch on a bit of one or an
 * index derived from it leaks it to anything watching the branch predictor or
 * the cache. The spec's reference is written for clarity and this is not. */
static uint8_t gf_mul(uint8_t a, uint8_t b)
{
    uint8_t res = 0;
    int i;

    for (i = 0; i < 5; i++) {
        /* 0 or 0xff, so the xor either lands whole or not at all */
        res ^= a & (uint8_t)-(int8_t)((b >> i) & 1);
        a = (uint8_t)(a << 1);
        a ^= 41 & (uint8_t)-(int8_t)((a >> 5) & 1);
        a &= 31;
    }
    return res;
}

static const uint8_t GF_INV[32] = {
     0,  1, 20, 24, 10,  8, 12, 29,  5, 11,  4,  9,  6, 28, 26, 31,
    22, 18, 17, 23,  2, 25, 16, 19,  3, 21, 14, 30, 13,  7, 27, 15
};

/* Lagrange weights at (x) for the share indices (idx), which the caller has
   already checked are distinct. */
static void lagrange(const uint8_t *idx, size_t m, uint8_t x, uint8_t *w)
{
    uint8_t n = 1;
    size_t i, j;

    for (i = 0; i < m; i++) n = gf_mul(n, (uint8_t)(idx[i] ^ x));
    for (i = 0; i < m; i++) {
        uint8_t d = 1;
        for (j = 0; j < m; j++)
            d = gf_mul(d, (uint8_t)((i == j ? x : idx[i]) ^ idx[j]));
        w[i] = gf_mul(n, GF_INV[d]);
    }
}

/* Interpolate the whole data part at share index (x). The threshold and
   identifier symbols are the same in every share, so they interpolate to
   themselves, and symbol 5 interpolates to x. */
static void interpolate(const kw_codex32 *in, size_t m, uint8_t x, kw_codex32 *out)
{
    uint8_t idx[KW_CODEX32_MAX_SHARES], w[KW_CODEX32_MAX_SHARES];
    size_t i, j;

    for (j = 0; j < m; j++) idx[j] = in[j].sym[5];
    lagrange(idx, m, x, w);

    out->nsym = in[0].nsym;
    for (i = 0; i < out->nsym; i++) {
        uint8_t v = 0;
        for (j = 0; j < m; j++) v ^= gf_mul(w[j], in[j].sym[i]);
        out->sym[i] = v;
    }
    kw_secure_zero(w, sizeof w);
}

/* strchr finds the terminating NUL, so an empty character would otherwise come
   back as index 32 and be written into a symbol the encoder then refuses. */
static int charval(char c)
{
    const char *p = c ? strchr(CHARSET, c) : NULL;

    return p ? (int)(p - CHARSET) : -1;
}

kw_codex32_err kw_codex32_decode(const char *s, kw_codex32 *out)
{
    uint8_t data[KW_CODEX32_MAX_SYM + CHECK_LONG];
    char low[KW_CODEX32_MAX_LEN];
    size_t len, ndata, i;
    int upper = 0, lower = 0;

    if (!s || !out) return KW_CODEX32_ARG;
    len = strlen(s);

    for (i = 0; i < 6; i++) if (len == VALID_LENGTHS[i]) break;
    if (i == 6) return KW_CODEX32_LENGTH;
    if (len >= sizeof low) return KW_CODEX32_LENGTH;

    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 33 || c > 126) return KW_CODEX32_CHARSET;
        if (c >= 'A' && c <= 'Z') upper = 1;
        if (c >= 'a' && c <= 'z') lower = 1;
        low[i] = (char)((c >= 'A' && c <= 'Z') ? c - 'A' + 'a' : (char)c);
    }
    low[len] = '\0';
    if (upper && lower) return KW_CODEX32_CHARSET;

    /* "1" is not in the bech32 charset, so the separator can only be at 2. */
    if (low[0] != 'm' || low[1] != 's' || low[2] != '1') return KW_CODEX32_PREFIX;

    ndata = len - 3;
    for (i = 0; i < ndata; i++) {
        int v = charval(low[3 + i]);
        if (v < 0) return KW_CODEX32_CHARSET;
        data[i] = (uint8_t)v;
    }

    /* The threshold must be a digit, which rules out 1 as well since "1" is
       not a bech32 character. A threshold of 0 means unshared, so its index
       has to be the secret's. */
    if (low[3] < '0' || low[3] > '9') return KW_CODEX32_PREFIX;
    if (low[3] == '0' && low[8] != 's') return KW_CODEX32_PREFIX;

    if (!verify_checksum(data, ndata)) return KW_CODEX32_CHECKSUM;

    out->nsym = ndata - (is_long(ndata) ? CHECK_LONG : CHECK_SHORT);
    memcpy(out->sym, data, out->nsym);
    memset(out->sym + out->nsym, 0, sizeof out->sym - out->nsym);
    kw_secure_zero(data, sizeof data);
    return KW_CODEX32_OK;
}

kw_codex32_err kw_codex32_encode(const kw_codex32 *c, char *out, size_t outcap)
{
    uint8_t data[KW_CODEX32_MAX_SYM + CHECK_LONG];
    size_t nck, total, i;

    if (!c || !out) return KW_CODEX32_ARG;
    if (c->nsym < HEADER_SYM || c->nsym > KW_CODEX32_MAX_SYM) return KW_CODEX32_ARG;
    for (i = 0; i < c->nsym; i++) if (c->sym[i] > 31) return KW_CODEX32_ARG;

    memcpy(data, c->sym, c->nsym);
    nck = create_checksum(data, c->nsym);
    total = 3 + c->nsym + nck;

    for (i = 0; i < 6; i++) if (total == VALID_LENGTHS[i]) break;
    if (i == 6) { kw_secure_zero(data, sizeof data); return KW_CODEX32_LENGTH; }
    if (total + 1 > outcap) { kw_secure_zero(data, sizeof data); return KW_CODEX32_ARG; }

    out[0] = 'm';
    out[1] = 's';
    out[2] = '1';
    for (i = 0; i < c->nsym + nck; i++) out[3 + i] = CHARSET[data[i]];
    out[total] = '\0';
    kw_secure_zero(data, sizeof data);
    return KW_CODEX32_OK;
}

uint8_t kw_codex32_threshold(const kw_codex32 *c)
{
    char ch = CHARSET[c->sym[0] & 31];

    if (ch == '0') return 0;
    if (ch >= '2' && ch <= '9') return (uint8_t)(ch - '0');
    return 0xff;                       /* not a digit, which decode refuses */
}

uint8_t kw_codex32_index(const kw_codex32 *c)
{
    return c->sym[5];
}

void kw_codex32_id(const kw_codex32 *c, char out[5])
{
    int i;

    for (i = 0; i < 4; i++) out[i] = CHARSET[c->sym[1 + i] & 31];
    out[4] = '\0';
}

kw_codex32_err kw_codex32_seed(const kw_codex32 *c, uint8_t *out, size_t outcap,
                               size_t *outlen)
{
    size_t npay, bits, n, i;
    uint32_t acc = 0;
    int nacc = 0;

    if (!c || !out || !outlen) return KW_CODEX32_ARG;
    if (c->nsym < HEADER_SYM + 1) return KW_CODEX32_ARG;

    npay = c->nsym - HEADER_SYM;
    bits = npay * 5;
    n = bits / 8;
    if (bits % 8 > 4) return KW_CODEX32_LENGTH;
    if (n > outcap) return KW_CODEX32_ARG;

    for (i = 0, *outlen = 0; i < npay; i++) {
        acc = (acc << 5) | c->sym[HEADER_SYM + i];
        nacc += 5;
        while (nacc >= 8) {
            nacc -= 8;
            out[(*outlen)++] = (uint8_t)((acc >> nacc) & 0xff);
        }
    }
    return KW_CODEX32_OK;
}

/* The threshold digit as a bech32 symbol value. */
static int threshold_sym(uint8_t t)
{
    char c;

    if (t == 0) c = '0';
    else if (t >= 2 && t <= 9) c = (char)('0' + t);
    else return -1;
    return charval(c);
}

kw_codex32_err kw_codex32_from_seed(uint8_t threshold, const char *id,
                                    const uint8_t *seed, size_t seedlen,
                                    kw_codex32 *out)
{
    size_t npay, i, k;
    uint32_t acc = 0;
    int nacc = 0, t;

    if (!id || !seed || !out) return KW_CODEX32_ARG;
    if (strlen(id) != 4) return KW_CODEX32_ARG;
    if (seedlen != 16 && seedlen != 20 && seedlen != 24 && seedlen != 28 &&
        seedlen != 32 && seedlen != 64)
        return KW_CODEX32_ARG;
    if ((t = threshold_sym(threshold)) < 0) return KW_CODEX32_ARG;

    memset(out, 0, sizeof *out);
    out->sym[0] = (uint8_t)t;
    for (i = 0; i < 4; i++) {
        int v = charval(id[i]);
        if (v < 0) return KW_CODEX32_CHARSET;
        out->sym[1 + i] = (uint8_t)v;
    }
    out->sym[5] = KW_CODEX32_SECRET;

    npay = (seedlen * 8 + 4) / 5;
    out->nsym = HEADER_SYM + npay;
    for (i = 0, k = 0; i < seedlen; i++) {
        acc = (acc << 8) | seed[i];
        nacc += 8;
        while (nacc >= 5) {
            nacc -= 5;
            out->sym[HEADER_SYM + k++] = (uint8_t)((acc >> nacc) & 31);
        }
    }
    if (nacc) out->sym[HEADER_SYM + k++] = (uint8_t)((acc << (5 - nacc)) & 31);
    if (k != npay) return KW_CODEX32_ARG;
    return KW_CODEX32_OK;
}

/* Every share in a set must agree on everything but its own index, and the
   indices must be distinct. */
static kw_codex32_err check_set(const kw_codex32 *c, size_t n)
{
    size_t i, j;
    uint8_t t;

    if (n == 0) return KW_CODEX32_ARG;
    t = kw_codex32_threshold(&c[0]);
    if (t < 2 || t > 9) return KW_CODEX32_GROUPING;
    if (n != t) return KW_CODEX32_GROUPING;

    for (i = 0; i < n; i++) {
        if (c[i].nsym != c[0].nsym) return KW_CODEX32_GROUPING;
        if (memcmp(c[i].sym, c[0].sym, 5) != 0) return KW_CODEX32_GROUPING;
        for (j = i + 1; j < n; j++)
            if (c[i].sym[5] == c[j].sym[5]) return KW_CODEX32_GROUPING;
    }
    return KW_CODEX32_OK;
}

kw_codex32_err kw_codex32_split(const uint8_t *seed, size_t seedlen,
                                const char *id, uint8_t threshold, uint8_t count,
                                char *out, size_t stride, size_t *nout)
{
    kw_codex32 base[KW_CODEX32_MAX_SHARES + 1], share;
    uint8_t taken[32];
    char idbuf[5];
    kw_codex32_err err = KW_CODEX32_OK;
    size_t npay, i, k = 0, nbase = 0;
    uint8_t rnd[KW_CODEX32_MAX_SYM];

    if (!seed || !out || !nout) return KW_CODEX32_ARG;
    if (stride < KW_CODEX32_MAX_LEN) return KW_CODEX32_ARG;
    /* BIP-93 has no threshold of 1: an unshared secret is threshold 0 and index
       "s", which is the seed itself rather than a share of it. */
    if (threshold < 2 || threshold > 9) return KW_CODEX32_ARG;
    if (count < threshold || count > KW_CODEX32_MAX_SHARES) return KW_CODEX32_ARG;
    if (id && strlen(id) != 4) return KW_CODEX32_ARG;

    if (id) {
        memcpy(idbuf, id, 4);
        idbuf[4] = '\0';
    } else {
        uint8_t r[4];
        if (!kw_random_bytes(r, sizeof r)) return KW_CODEX32_RNG;
        for (i = 0; i < 4; i++) idbuf[i] = CHARSET[r[i] & 31];
        idbuf[4] = '\0';
    }

    memset(taken, 0, sizeof taken);
    kw_secure_keep(base, sizeof base);
    kw_secure_keep(&share, sizeof share);

    /* The secret and threshold - 1 random shares are the k strings every other
       share is interpolated from. The secret is one of them and is not handed
       out, so the random ones count toward (count). */
    if ((err = kw_codex32_from_seed(threshold, idbuf, seed, seedlen, &base[0]))
        != KW_CODEX32_OK)
        goto out;
    taken[KW_CODEX32_SECRET] = 1;
    nbase = 1;
    npay = base[0].nsym - HEADER_SYM;

    for (i = 0; i + 1 < threshold; i++) {
        size_t j;
        if (!kw_random_bytes(rnd, npay)) { err = KW_CODEX32_RNG; goto out; }
        base[nbase] = base[0];
        base[nbase].sym[5] = (uint8_t)charval(SHARE_LETTERS[i]);
        /* 256 is a multiple of 32, so masking a uniform byte stays uniform. */
        for (j = 0; j < npay; j++) base[nbase].sym[HEADER_SYM + j] = rnd[j] & 31;
        taken[base[nbase].sym[5]] = 1;
        nbase++;
    }

    /* The random shares are the first of the output; the rest are interpolated
       at the next free letters. */
    for (i = 1; i < nbase; i++) {
        if ((err = kw_codex32_encode(&base[i], out + (i - 1) * stride, stride))
            != KW_CODEX32_OK)
            goto out;
    }
    k = nbase - 1;

    for (i = 0; k < count; i++) {
        uint8_t x;
        if (i >= sizeof SHARE_LETTERS - 1) { err = KW_CODEX32_ARG; goto out; }
        x = (uint8_t)charval(SHARE_LETTERS[i]);
        if (taken[x]) continue;
        interpolate(base, nbase, x, &share);
        if ((err = kw_codex32_encode(&share, out + k * stride, stride)) != KW_CODEX32_OK)
            goto out;
        taken[x] = 1;
        k++;
    }

    *nout = count;

out:
    kw_secure_zero(rnd, sizeof rnd);
    kw_secure_zero(base, sizeof base);
    kw_secure_zero(&share, sizeof share);
    kw_secure_forget(base, sizeof base);
    kw_secure_forget(&share, sizeof share);
    if (err != KW_CODEX32_OK) {
        for (i = 0; i < k; i++) kw_secure_zero(out + i * stride, stride);
        *nout = 0;
    }
    return err;
}

/* Decode (n) strings and check they form one threshold set. The secret counts
   toward a threshold for deriving a further share, which is how BIP-93 says to
   split an existing seed, and is not a share of itself for combining. */
static kw_codex32_err load_set(const char *const *strings, size_t n, int allow_secret,
                               kw_codex32 *c)
{
    kw_codex32_err err;
    size_t i;

    if (!strings || n == 0 || n > KW_CODEX32_MAX_SHARES) return KW_CODEX32_ARG;
    for (i = 0; i < n; i++) {
        if ((err = kw_codex32_decode(strings[i], &c[i])) != KW_CODEX32_OK) return err;
        if (!allow_secret && c[i].sym[5] == KW_CODEX32_SECRET) return KW_CODEX32_GROUPING;
    }
    return check_set(c, n);
}

kw_codex32_err kw_codex32_combine(const char *const *shares, size_t n,
                                  uint8_t *out, size_t outcap, size_t *outlen)
{
    kw_codex32 c[KW_CODEX32_MAX_SHARES], secret;
    kw_codex32_err err;

    if (!out || !outlen) return KW_CODEX32_ARG;

    kw_secure_keep(c, sizeof c);
    kw_secure_keep(&secret, sizeof secret);

    if ((err = load_set(shares, n, 0, c)) != KW_CODEX32_OK) goto out;
    interpolate(c, n, KW_CODEX32_SECRET, &secret);
    err = kw_codex32_seed(&secret, out, outcap, outlen);

out:
    kw_secure_zero(c, sizeof c);
    kw_secure_zero(&secret, sizeof secret);
    kw_secure_forget(c, sizeof c);
    kw_secure_forget(&secret, sizeof secret);
    if (err != KW_CODEX32_OK) {
        kw_secure_zero(out, outcap);
        *outlen = 0;
    }
    return err;
}

kw_codex32_err kw_codex32_derive(const char *const *shares, size_t n,
                                 uint8_t index, char *out, size_t outcap)
{
    kw_codex32 c[KW_CODEX32_MAX_SHARES], fresh;
    kw_codex32_err err;
    size_t i;

    if (!out || index > 31 || index == KW_CODEX32_SECRET) return KW_CODEX32_ARG;

    kw_secure_keep(c, sizeof c);
    kw_secure_keep(&fresh, sizeof fresh);

    if ((err = load_set(shares, n, 1, c)) != KW_CODEX32_OK) goto out;
    for (i = 0; i < n; i++)
        if (c[i].sym[5] == index) { err = KW_CODEX32_GROUPING; goto out; }

    interpolate(c, n, index, &fresh);
    err = kw_codex32_encode(&fresh, out, outcap);

out:
    kw_secure_zero(c, sizeof c);
    kw_secure_zero(&fresh, sizeof fresh);
    kw_secure_forget(c, sizeof c);
    kw_secure_forget(&fresh, sizeof fresh);
    if (err != KW_CODEX32_OK && outcap) kw_secure_zero(out, outcap);
    return err;
}
