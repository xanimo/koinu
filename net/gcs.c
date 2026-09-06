/* koinu.dog - BIP158 basic block filter (Golomb-coded set)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "gcs.h"
#include "siphash.h"

#include <stdlib.h>

/* map a 64-bit hash uniformly into [0, F) */
static uint64_t hash_to_range(uint64_t v, uint64_t F)
{
    return (uint64_t)(((__uint128_t)v * (__uint128_t)F) >> 64);
}

uint64_t kw_gcs_hash(const uint8_t block_hash[32], uint64_t N,
                     const uint8_t *e, size_t elen)
{
    uint64_t v = kw_siphash24(block_hash, e, elen);   /* key = first 16 bytes */
    return hash_to_range(v, N * (uint64_t)KW_GCS_M);
}

/* varint at the front of the filter; sets *off past it */
static long read_varint(const uint8_t *p, size_t len, size_t *off)
{
    if (*off >= len) return -1;
    uint8_t pfx = p[(*off)++];
    int n = pfx < 0xfd ? 0 : pfx == 0xfd ? 2 : pfx == 0xfe ? 4 : 8;
    if (n == 0) return pfx;
    if (*off + (size_t)n > len) return -1;
    uint64_t v = 0;
    for (int i = 0; i < n; i++) v |= (uint64_t)p[*off + i] << (8 * i);
    *off += (size_t)n;
    return (long)v;
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
    long N = read_varint(filt, flen, &off);
    if (N < 0 || (size_t)N > cap) return -1;
    bitr b = { filt + off, (flen - off) * 8, 0, 0 };
    uint64_t val = 0;
    for (long i = 0; i < N; i++) {
        val += gr_next(&b);
        if (b.bad) return -1;
        out[i] = val;
    }
    return N;
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
    long N = read_varint(filt, flen, &off);
    if (N < 0) return -1;
    if (N == 0 || nitems == 0) return 0;

    uint64_t F = (uint64_t)N * (uint64_t)KW_GCS_M;
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
    for (long i = 0; i < N && !found; i++) {
        val += gr_next(&b);
        if (b.bad) { free(tv); return -1; }
        while (ti < nitems && tv[ti] < val) ti++;
        if (ti < nitems && tv[ti] == val) found = 1;
    }
    free(tv);
    return found;
}
