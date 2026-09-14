/* koinu.dog - on-disk BIP158 filter cache
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "cfstore.h"
#include "cf.h"
#include "sync.h"
#include "sha2.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

static const char KW_CF_MAGIC[4] = { 'K', 'W', 'F', '1' };
static const char KW_FH_MAGIC[4] = { 'K', 'W', 'F', 'H' };

/* The verified filter-header tip in <path>.fh: tag, entry count (8 LE), the
   filter header after that many entries. Binds a later delta sync to the chain
   already verified, so the peer cannot quietly rewrite cached history. */
static int fh_load(const char *path, long *count, uint8_t hdr[32])
{
    char fp[4200]; snprintf(fp, sizeof fp, "%s.fh", path);
    FILE *f = fopen(fp, "rb");
    if (!f) return 0;
    uint8_t buf[4 + 8 + 32];
    int ok = fread(buf, 1, sizeof buf, f) == sizeof buf &&
             memcmp(buf, KW_FH_MAGIC, 4) == 0;
    fclose(f);
    if (!ok) return 0;
    long c = 0;
    for (int i = 0; i < 8; i++) c |= (long)buf[4 + i] << (8 * i);
    *count = c;
    memcpy(hdr, buf + 12, 32);
    return 1;
}

static int fh_save(const char *path, long count, const uint8_t hdr[32])
{
    char fp[4200]; snprintf(fp, sizeof fp, "%s.fh", path);
    FILE *f = fopen(fp, "wb");
    if (!f) return 0;
    uint8_t buf[4 + 8 + 32];
    memcpy(buf, KW_FH_MAGIC, 4);
    for (int i = 0; i < 8; i++) buf[4 + i] = (uint8_t)((uint64_t)count >> (8 * i));
    memcpy(buf + 12, hdr, 32);
    int ok = fwrite(buf, 1, sizeof buf, f) == sizeof buf;
    if (fclose(f) != 0) ok = 0;
    return ok;
}

static int  ensure_index(const char *path);
static long index_count(const char *path);
static long index_offset(const char *path, size_t idx);

static int wr_varint(FILE *f, uint64_t v)
{
    uint8_t b[9]; size_t n = 0;
    if (v < 0xfd) b[n++] = (uint8_t)v;
    else if (v <= 0xffff) { b[n++] = 0xfd; b[n++] = (uint8_t)v; b[n++] = (uint8_t)(v >> 8); }
    else if (v <= 0xffffffff) { b[n++] = 0xfe; for (int i = 0; i < 4; i++) b[n++] = (uint8_t)(v >> (8 * i)); }
    else { b[n++] = 0xff; for (int i = 0; i < 8; i++) b[n++] = (uint8_t)(v >> (8 * i)); }
    return fwrite(b, 1, n, f) == n;
}

/* A basic filter is a byte or two per element and a block is bounded, so nothing
   legitimate comes near this. It exists because the length is read out of the cache:
   cast to long an unbounded value can go negative and seek backwards, which turns the
   rewrite loop below into one that never ends. */
#define KW_CFSTORE_MAX_FILTER (4u << 20)

static int rd_varint(FILE *f, uint64_t *out)
{
    int c = fgetc(f);
    if (c == EOF) return 0;
    if (c < 0xfd) { *out = (uint64_t)c; return 1; }
    int n = c == 0xfd ? 2 : c == 0xfe ? 4 : 8;
    uint64_t v = 0;
    for (int i = 0; i < n; i++) { int b = fgetc(f); if (b == EOF) return 0; v |= (uint64_t)b << (8 * i); }
    *out = v;
    return 1;
}

int kw_cfstore_append(const char *path, const uint8_t block_hash[32],
                      const uint8_t *filter, size_t flen)
{
    FILE *f = fopen(path, "ab");
    if (!f) return 0;
    int ok = 1;
    if (ftell(f) == 0) ok = fwrite(KW_CF_MAGIC, 1, 4, f) == 4;   /* new file: tag it */
    if (ok) ok = fwrite(block_hash, 1, 32, f) == 32;
    if (ok) ok = wr_varint(f, flen);
    if (ok && flen) ok = fwrite(filter, 1, flen, f) == flen;
    if (fclose(f) != 0) ok = 0;
    return ok;
}

long kw_cfstore_count(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    char m[4];
    if (fread(m, 1, 4, f) != 4 || memcmp(m, KW_CF_MAGIC, 4) != 0) { fclose(f); return -1; }
    long n = 0;
    for (;;) {
        uint8_t h[32];
        size_t r = fread(h, 1, 32, f);
        if (r == 0) break;
        if (r != 32) { fclose(f); return -1; }
        uint64_t fl;
        if (!rd_varint(f, &fl) || fl > KW_CFSTORE_MAX_FILTER ||
            fseek(f, (long)fl, SEEK_CUR) != 0) { fclose(f); return -1; }
        n++;
    }
    fclose(f);
    return n;
}

long kw_cfstore_sync(kw_peer *p, const kw_headerstore *s, const char *path,
                     uint32_t base_height)
{
    /* count via the index (O(1)) rather than streaming the whole cache */
    long have;
    FILE *tf = fopen(path, "rb");
    if (!tf) have = 0;                                       /* no cache yet */
    else {
        fclose(tf);
        if (!ensure_index(path)) return -1;                 /* present but corrupt */
        have = index_count(path);
    }
    if (have < 0 || (size_t)have > s->count) return -1;      /* corrupt or ahead of headers */

    /* Resume the verified filter-header chain. Cached filters on their own prove
       nothing: the sidecar is what ties them to a chain this wallet checked, so a
       cache with no sidecar is refused rather than adopted, and a cache reaching
       past the sidecar has the unbacked tail dropped. Re-adopting either from the
       peer would hand back the trust-on-first-use the sidecar exists to end. */
    uint8_t chain[32]; int have_chain = 0;
    long fhc = 0;
    if (have > 0) {
        if (!fh_load(path, &fhc, chain) || fhc < 0 || fhc > have) {
            fprintf(stderr, "kw: %s.fh is missing or does not match %s, so those filters "
                            "cannot be tied to a verified chain; delete both and sync again\n",
                    path, path);
            return -1;
        }
        if (fhc < have) {
            long at = index_offset(path, (size_t)fhc);
            char ip[4200]; snprintf(ip, sizeof ip, "%s.idx", path);
            if (at < 4 || truncate(path, (off_t)at) != 0) {
                fprintf(stderr, "kw: cannot drop the unverified tail of %s\n", path);
                return -1;
            }
            remove(ip);                                  /* rebuilt against the new size */
            fprintf(stderr, "kw: dropped %ld filters past the verified tip of %s\n",
                    have - fhc, path);
            have = fhc;
            if (have > 0 && !ensure_index(path)) return -1;
        }
        have_chain = have > 0;
    }
    if ((size_t)have == s->count) return (long)s->count;

    uint8_t (*fh)[32] = (uint8_t (*)[32])malloc(1000 * 32);
    if (!fh) return -1;

    const size_t CHUNK = 1000;
    for (size_t s0 = (size_t)have; s0 < s->count; s0 += CHUNK) {
        size_t s1 = s0 + CHUNK;
        if (s1 > s->count) s1 = s->count;

        uint8_t prev[32];
        if (!kw_cf_fetch_headers(p, s, base_height, s0, s1, prev, fh)) { free(fh); return -1; }
        if (have_chain && memcmp(prev, chain, 32) != 0) {
            if (kw_net_verbose) fprintf(stderr, "[cf] filter-header chain broke at height %u\n",
                                        base_height + (uint32_t)s0);
            free(fh); return -1;
        }
        /* prev is the chain at the block before this range, so an anchor there
           is checked before a single filter of the range is trusted */
        if (s0 > 0 && !kw_cf_anchor_ok(p->cp, base_height + (uint32_t)s0 - 1, prev)) { free(fh); return -1; }
        memcpy(chain, prev, 32); have_chain = 1;

        uint8_t body[37];
        size_t bn = kw_msg_getcfilters_build(KW_CF_TYPE_BASIC, base_height + (uint32_t)s0,
                                             s->h[s1 - 1].hash, body, sizeof body);
        if (!bn || !kw_peer_send(p, "getcfilters", body, bn)) { free(fh); return -1; }

        for (size_t k = s0; k < s1; k++) {
            char cmd[13]; const uint8_t *pl = NULL; size_t pn = 0;
            int got = 0;
            while (kw_peer_recv(p, cmd, &pl, &pn) == 1) {
                if (!strcmp(cmd, "cfilter")) { got = 1; break; }
                if (!strcmp(cmd, "ping")) kw_peer_send(p, "pong", pl, pn);
            }
            if (!got) { free(fh); return -1; }

            uint8_t type, bh[32]; const uint8_t *filt; size_t flen;
            if (!kw_msg_cfilter_parse(pl, pn, &type, bh, &filt, &flen)) { free(fh); return -1; }
            if (type != KW_CF_TYPE_BASIC || memcmp(bh, s->h[k].hash, 32) != 0) { free(fh); return -1; }

            uint8_t fhash[32];
            kw_hash256(filt, flen, fhash);
            if (memcmp(fhash, fh[k - s0], 32) != 0) {
                if (kw_net_verbose) fprintf(stderr, "[cf] filter commitment mismatch at height %u\n",
                                            base_height + (uint32_t)k);
                free(fh); return -1;
            }
            kw_cf_header_step(fhash, chain, chain);
            if (!kw_cf_anchor_ok(p->cp, base_height + (uint32_t)k, chain)) { free(fh); return -1; }

            if (!kw_cfstore_append(path, bh, filt, flen)) { free(fh); return -1; }
        }
        if (!fh_save(path, (long)s1, chain)) { free(fh); return -1; }
        if (kw_net_verbose) fprintf(stderr, "[cf] cached %zu/%zu filters\n", s1, s->count);
    }
    free(fh);
    return (long)s->count;
}

/* Write entry offsets to (of), starting at cache position (from) and updating
   the 8-byte header to (csize) at the end. (cf) is positioned at (from). */
static int index_write_from(FILE *cf, FILE *of, long from, long csize)
{
    int ok = 1;
    long pos = from;
    for (;;) {
        uint8_t h[32];
        size_t r = fread(h, 1, 32, cf);
        if (r == 0) break;
        if (r != 32) { ok = 0; break; }
        uint64_t fl;
        /* fl comes off the cache. Cast to long it could go negative and seek
           backwards, and the loop that follows would rewrite the index forever. */
        if (!rd_varint(cf, &fl) || fl > KW_CFSTORE_MAX_FILTER ||
            fseek(cf, (long)fl, SEEK_CUR) != 0) { ok = 0; break; }
        uint8_t ob[8];
        for (int i = 0; i < 8; i++) ob[i] = (uint8_t)((uint64_t)pos >> (8 * i));
        if (fwrite(ob, 1, 8, of) != 8) { ok = 0; break; }
        pos = ftell(cf);
    }
    if (ok) {
        uint8_t hd[8];
        for (int i = 0; i < 8; i++) hd[i] = (uint8_t)((uint64_t)csize >> (8 * i));
        if (fseek(of, 0, SEEK_SET) != 0 || fwrite(hd, 1, 8, of) != 8) ok = 0;
    }
    return ok;
}

/* Build or extend the <path>.idx height index: an 8-byte cache size then a
   uint64 file offset per entry. Current when the stored size equals the cache's;
   since the cache is append-only, a grown cache only needs its new tail indexed
   rather than a full rebuild. Returns 1/0. */
static int ensure_index(const char *path)
{
    char ip[4200]; snprintf(ip, sizeof ip, "%s.idx", path);

    FILE *cf = fopen(path, "rb");
    if (!cf) return 0;
    if (fseek(cf, 0, SEEK_END) != 0) { fclose(cf); return 0; }
    long csize = ftell(cf);

    long stored = -1;
    FILE *xf = fopen(ip, "rb");
    if (xf) {
        uint8_t hd[8];
        if (fread(hd, 1, 8, xf) == 8) { stored = 0; for (int i = 0; i < 8; i++) stored |= (long)hd[i] << (8 * i); }
        fclose(xf);
    }
    if (stored == csize) { fclose(cf); return 1; }                 /* current */

    /* append-only: extend from the previously indexed end */
    if (stored > 4 && stored < csize) {
        FILE *of = fopen(ip, "r+b");
        if (of && fseek(cf, stored, SEEK_SET) == 0 && fseek(of, 0, SEEK_END) == 0) {
            int ok = index_write_from(cf, of, stored, csize);
            if (fclose(of) != 0) ok = 0;
            fclose(cf);
            if (ok) return 1;
            cf = fopen(path, "rb");                                /* extend failed: fall to rebuild */
            if (!cf) return 0;
        } else if (of) fclose(of);
    }

    /* full rebuild */
    if (fseek(cf, 0, SEEK_SET) != 0) { fclose(cf); return 0; }
    char m[4];
    if (fread(m, 1, 4, cf) != 4 || memcmp(m, KW_CF_MAGIC, 4) != 0) { fclose(cf); return 0; }
    FILE *of = fopen(ip, "wb");
    if (!of) { fclose(cf); return 0; }
    uint8_t hd0[8] = {0};
    int ok = fwrite(hd0, 1, 8, of) == 8;                           /* placeholder header */
    if (ok) ok = index_write_from(cf, of, 4, csize);
    if (fclose(of) != 0) ok = 0;
    fclose(cf);
    return ok;
}

/* Read the file offset of entry (idx) from the index; -1 if unavailable. */
static long index_offset(const char *path, size_t idx)
{
    char ip[4200]; snprintf(ip, sizeof ip, "%s.idx", path);
    FILE *xf = fopen(ip, "rb");
    if (!xf) return -1;
    long r = -1;
    if (fseek(xf, (long)(8 + idx * 8), SEEK_SET) == 0) {
        uint8_t ob[8];
        if (fread(ob, 1, 8, xf) == 8) {
            uint64_t v = 0;
            for (int i = 0; i < 8; i++) v |= (uint64_t)ob[i] << (8 * i);
            r = (long)v;
        }
    }
    fclose(xf);
    return r;
}

static long index_count(const char *path)
{
    char ip[4200]; snprintf(ip, sizeof ip, "%s.idx", path);
    FILE *xf = fopen(ip, "rb");
    if (!xf) return -1;
    long sz = (fseek(xf, 0, SEEK_END) == 0) ? ftell(xf) : -1;
    fclose(xf);
    return sz < 8 ? -1 : (sz - 8) / 8;
}

long kw_cfstore_match_range(const char *path, const kw_headerstore *s, uint32_t base_height,
                            uint32_t from_height, const kw_gcs_item *items, size_t nitems,
                            uint32_t *heights, size_t cap)
{
    if (!ensure_index(path)) return -1;
    long cnt = index_count(path);
    if (cnt < 0) return -1;

    size_t start = (from_height > base_height) ? (size_t)(from_height - base_height) : 0;
    if (start >= (size_t)cnt) return 0;              /* range past the tip */

    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (start > 0) {
        long o = index_offset(path, start);
        if (o < 0 || fseek(f, o, SEEK_SET) != 0) { fclose(f); return -1; }
    } else if (fseek(f, 4, SEEK_SET) != 0) { fclose(f); return -1; }   /* past the tag */

    uint8_t *buf = NULL; size_t bcap = 0;
    long n = 0; size_t idx = start;
    for (;;) {
        uint8_t h[32];
        size_t r = fread(h, 1, 32, f);
        if (r == 0) break;
        if (r != 32) { free(buf); fclose(f); return -1; }
        uint64_t fl;
        if (!rd_varint(f, &fl)) { free(buf); fclose(f); return -1; }
        if (fl > KW_CFSTORE_MAX_FILTER) { free(buf); fclose(f); return -1; }
        if (fl > bcap) { uint8_t *nb = realloc(buf, (size_t)fl); if (!nb) { free(buf); fclose(f); return -1; } buf = nb; bcap = (size_t)fl; }
        if (fl && fread(buf, 1, (size_t)fl, f) != (size_t)fl) { free(buf); fclose(f); return -1; }

        if (s && (idx >= s->count || memcmp(h, s->h[idx].hash, 32) != 0)) { free(buf); fclose(f); return -1; }
        int mm = nitems ? kw_gcs_match_any(buf, (size_t)fl, h, items, nitems) : 0;
        if (mm < 0) { free(buf); fclose(f); return -1; }
        if (mm == 1 && (size_t)n < cap) heights[n++] = base_height + (uint32_t)idx;
        idx++;
    }
    free(buf);
    fclose(f);
    return n;
}

long kw_cfstore_match(const char *path, const kw_headerstore *s, uint32_t base_height,
                      const kw_gcs_item *items, size_t nitems,
                      uint32_t *heights, size_t cap)
{
    return kw_cfstore_match_range(path, s, base_height, base_height, items, nitems, heights, cap);
}
