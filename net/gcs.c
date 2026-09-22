/* koinu.dog - BIP158 basic block filter (Golomb-coded set)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "gcs.h"
#include "siphash.h"

#include <stdlib.h>

/* Map a 64-bit hash uniformly into [0, F): the high half of the 128-bit
   product. __uint128_t is a 64-bit-target extension, so the fallback does the
   same multiply in 32-bit halves rather than leaving the filter unbuildable
   where it is absent. */
static uint64_t hash_to_range(uint64_t v, uint64_t F)
{
#ifdef __SIZEOF_INT128__
    return (uint64_t)(((__uint128_t)v * (__uint128_t)F) >> 64);
#else
    uint64_t vlo = v & 0xffffffffULL, vhi = v >> 32;
    uint64_t flo = F & 0xffffffffULL, fhi = F >> 32;
    uint64_t ll = vlo * flo, lh = vlo * fhi;
    uint64_t hl = vhi * flo, hh = vhi * fhi;
    /* carry out of the low 64 bits, taken 32 at a time so nothing overflows */
    uint64_t mid = (ll >> 32) + (lh & 0xffffffffULL) + (hl & 0xffffffffULL);
    return hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
#endif
}

uint64_t kw_gcs_hash(const uint8_t block_hash[32], uint64_t N,
                     const uint8_t *e, size_t elen)
{
    uint64_t v = kw_siphash24(block_hash, e, elen);   /* key = first 16 bytes */
    return hash_to_range(v, N * (uint64_t)KW_GCS_M);
}

/* varint at the front of the filter; sets *off past it */
/* Out-param rather than a return: the value is a uint64 and long is 32 bits on
   i386, where truncation turns an absurd N into a small one that passes the
   caller's bound instead of being refused. */
static int read_varint(const uint8_t *p, size_t len, size_t *off, uint64_t *out)
{
    if (*off >= len) return 0;
    uint8_t pfx = p[(*off)++];
    int n = pfx < 0xfd ? 0 : pfx == 0xfd ? 2 : pfx == 0xfe ? 4 : 8;
    if (n == 0) { *out = pfx; return 1; }
    if (len - *off < (size_t)n) return 0;
    uint64_t v = 0;
    for (int i = 0; i < n; i++) v |= (uint64_t)p[*off + i] << (8 * i);
    *off += (size_t)n;
    *out = v;
    return 1;
}

/* MSB-first bit reader over the Golomb-Rice stream */
typedef struct { const uint8_t *p; size_t nbits, pos; int bad; } bitr;
static int rbit(bitr *b)
{
    if (b->pos >= b->nbits) { b->bad = 1; return 0; }
    int v = (b->p[b->pos >> 3] >> (7 - (b->pos & 7))) & 1;
    b->pos++;
    return v;
}
static uint64_t rbits(bitr *b, int n)
{
    uint64_t v = 0;
    for (int i = 0; i < n; i++) v = (v << 1) | (uint64_t)rbit(b);
    return v;
}
static uint64_t gr_next(bitr *b)
{
    uint64_t q = 0;
    while (rbit(b) == 1) { q++; if (b->bad) return 0; }
    return (q << KW_GCS_P) + rbits(b, KW_GCS_P);
}

long kw_gcs_decode(const uint8_t *filt, size_t flen, uint64_t *out, size_t cap)
{
    size_t off = 0;
    uint64_t N;
    if (!read_varint(filt, flen, &off, &N) || N > cap) return -1;
    bitr b = { filt + off, (flen - off) * 8, 0, 0 };
    uint64_t val = 0;
    for (uint64_t i = 0; i < N; i++) {
        val += gr_next(&b);
        if (b.bad) return -1;
        out[i] = val;
    }
    return (long)N;
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

int kw_gcs_match_any(const uint8_t *filt, size_t flen, const uint8_t block_hash[32],
                     const kw_gcs_item *items, size_t nitems)
{
    size_t off = 0;
    uint64_t N;
    /* Each element costs at least one bit, so a claimed N past the remaining bits
       is a lie. Bounding it here also keeps N * KW_GCS_M below 2^64. */
    if (!read_varint(filt, flen, &off, &N) || N > (flen - off) * 8) return -1;
    if (N == 0 || nitems == 0) return 0;

    uint64_t F = N * (uint64_t)KW_GCS_M;
    uint64_t *tv = (uint64_t *)malloc(nitems * sizeof *tv);
    if (!tv) return -1;
    for (size_t i = 0; i < nitems; i++)
        tv[i] = hash_to_range(kw_siphash24(block_hash, items[i].script, items[i].len), F);
    qsort(tv, nitems, sizeof *tv, cmp_u64);

    /* merge the sorted targets against the filter's ascending set values */
    bitr b = { filt + off, (flen - off) * 8, 0, 0 };
    uint64_t val = 0;
    size_t ti = 0;
    int found = 0;
    for (uint64_t i = 0; i < N && !found; i++) {
        val += gr_next(&b);
        if (b.bad) { free(tv); return -1; }
        while (ti < nitems && tv[ti] < val) ti++;
        if (ti < nitems && tv[ti] == val) found = 1;
    }
    free(tv);
    return found;
}
