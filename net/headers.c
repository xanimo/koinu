/* koinu.dog - block headers, getheaders/headers, and the header chain
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "headers.h"
#include "auxpow.h"
#include "sha2.h"
#include "mem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static uint32_t rd_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}

int kw_block_header_parse(const uint8_t *in, size_t len, kw_block_header *h)
{
    if (len < KW_HEADER_LEN) return 0;
    memcpy(h->raw, in, KW_HEADER_LEN);
    kw_hash256(h->raw, KW_HEADER_LEN, h->hash);
    return 1;
}

const uint8_t *kw_block_header_prev(const kw_block_header *h) { return h->raw + 4; }
uint32_t kw_block_header_version(const kw_block_header *h) { return rd_le32(h->raw); }

/* ── writer for getheaders ───────────────────────────────────── */
typedef struct { uint8_t *p; size_t cap, len; int ok; } W;
static void w_bytes(W *w, const void *b, size_t n)
{
    if (!w->ok || w->len + n > w->cap) { w->ok = 0; return; }
    memcpy(w->p + w->len, b, n); w->len += n;
}
static void w_le32(W *w, uint32_t v) { uint8_t b[4]; for (int i=0;i<4;i++) b[i]=(uint8_t)(v>>(8*i)); w_bytes(w,b,4); }
static void w_varint(W *w, uint64_t v)
{
    if (v < 0xfd) { uint8_t b=(uint8_t)v; w_bytes(w,&b,1); }
    else if (v <= 0xffff) { uint8_t b[3]={0xfd,(uint8_t)v,(uint8_t)(v>>8)}; w_bytes(w,b,3); }
    else { uint8_t b[5]={0xfe,(uint8_t)v,(uint8_t)(v>>8),(uint8_t)(v>>16),(uint8_t)(v>>24)}; w_bytes(w,b,5); }
}

size_t kw_msg_getheaders_build(uint32_t version,
                               const uint8_t (*locators)[32], size_t nloc,
                               const uint8_t hash_stop[32],
                               uint8_t *out, size_t outcap)
{
    W w = { out, outcap, 0, 1 };
    w_le32(&w, version);
    w_varint(&w, nloc);
    for (size_t i = 0; i < nloc; i++) w_bytes(&w, locators[i], 32);
    if (hash_stop) w_bytes(&w, hash_stop, 32);
    else { uint8_t z[32] = {0}; w_bytes(&w, z, 32); }
    return w.ok ? w.len : 0;
}

/* ── reader for headers ──────────────────────────────────────── */
typedef struct { const uint8_t *p; size_t len, off; int bad; } R;

static uint64_t r_varint(R *r)
{
    if (r->off >= r->len) { r->bad = 1; return 0; }
    uint8_t pfx = r->p[r->off++];
    uint64_t v = 0; int n = 0;
    if (pfx < 0xfd) return pfx;
    else if (pfx == 0xfd) n = 2;
    else if (pfx == 0xfe) n = 4;
    else n = 8;
    if (r->off + (size_t)n > r->len) { r->bad = 1; return 0; }
    for (int i = 0; i < n; i++) v |= (uint64_t)r->p[r->off + i] << (8 * i);
    r->off += (size_t)n;
    return v;
}



/* Skip a serialized transaction, BIP144 auto-detecting the segwit marker the
   same way Core's deserializer does. Used only to step over the AuxPoW parent
   coinbase, which (Litecoin) can be segwit. */
/* Skip a CAuxPow: parent coinbase (CMerkleTx) + chain merkle branch + parent
   pure header, in Core's serialization order. */int kw_auxpow_skip(const uint8_t *in, size_t len, size_t *off)
{
    return kw_auxpow_parse(in, len, off, NULL);
}

int kw_msg_headers_parse(const uint8_t *in, size_t len,
                         kw_block_header *out, size_t maxout, size_t *nout)
{
    return kw_msg_headers_parse_cb(in, len, out, maxout, nout, NULL, NULL);
}

int kw_msg_headers_parse_cb(const uint8_t *in, size_t len,
                            kw_block_header *out, size_t maxout, size_t *nout,
                            kw_header_fn fn, void *ctx)
{
    R r = { in, len, 0, 0 };
    uint64_t count = r_varint(&r);
    if (r.bad) return 0;
    if (count > maxout || count > KW_MAX_HEADERS) return 0;

    for (uint64_t i = 0; i < count; i++) {
        if (r.off + KW_HEADER_LEN > r.len) return 0;
        uint32_t version = rd_le32(r.p + r.off);
        kw_block_header_parse(r.p + r.off, KW_HEADER_LEN, &out[i]);
        r.off += KW_HEADER_LEN;
        const uint8_t *aux = NULL;
        size_t auxlen = 0;
        if (version & KW_BLOCK_VERSION_AUXPOW) {          /* step over merged-mining data */
            size_t at = r.off;
            if (!kw_auxpow_parse(r.p, r.len, &r.off, NULL)) r.bad = 1;
            else { aux = r.p + at; auxlen = r.off - at; }
        }
        (void)r_varint(&r);            /* tx count, 0 in a headers message */
        if (r.bad) return 0;
        if (fn && !fn(ctx, &out[i], aux, auxlen)) return 0;
    }
    *nout = (size_t)count;
    return 1;
}

/* ── header store ────────────────────────────────────────────── */
int kw_headerstore_init(kw_headerstore *s)
{
    s->cap = 64;
    s->count = 0;
    s->h = (kw_block_header *)malloc(s->cap * sizeof *s->h);
    return s->h != NULL;
}

int kw_headerstore_append(kw_headerstore *s, const kw_block_header *h)
{
    if (s->count > 0) {
        const kw_block_header *tip = &s->h[s->count - 1];
        if (memcmp(kw_block_header_prev(h), tip->hash, 32) != 0) return 0;
    }
    if (s->count == s->cap) {
        size_t nc = s->cap * 2;
        kw_block_header *nh = (kw_block_header *)realloc(s->h, nc * sizeof *nh);
        if (!nh) return 0;
        s->h = nh; s->cap = nc;
    }
    s->h[s->count++] = *h;
    return 1;
}

const kw_block_header *kw_headerstore_tip(const kw_headerstore *s)
{
    return s->count ? &s->h[s->count - 1] : NULL;
}

void kw_headerstore_truncate(kw_headerstore *s, size_t n)
{
    if (s && n < s->count) s->count = n;
}

void kw_headerstore_free(kw_headerstore *s)
{
    free(s->h);
    s->h = NULL; s->count = s->cap = 0;
}

/* ── on-disk cache ───────────────────────────────────────────── */
static const uint8_t KW_HDR_MAGIC1[4] = { 'K', 'W', 'H', '1' };   /* raw only */
static const uint8_t KW_HDR_MAGIC2[4] = { 'K', 'W', 'H', '2' };   /* raw + hash */

int kw_headerstore_create(const char *path, size_t count)
{
    FILE *f = fopen(path, "wb");
    if (!f) return 0;
    int ok = fwrite(KW_HDR_MAGIC2, 1, 4, f) == 4 && fflush(f) == 0 &&
             ftruncate(fileno(f), (off_t)(4 + count * KW_HDR_REC)) == 0;
    if (fclose(f) != 0) ok = 0;
    return ok;
}

/* records already in a KWH2 file at (path) whose tail matches (s), so save can
   append the delta instead of rewriting; 0 if absent, not KWH2, or diverged */
static size_t save_prefix(const kw_headerstore *s, const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    uint8_t magic[4];
    size_t n = 0;
    if (fread(magic, 1, 4, f) == 4 && memcmp(magic, KW_HDR_MAGIC2, 4) == 0 &&
        fseek(f, 0, SEEK_END) == 0) {
        long sz = ftell(f);
        if (sz > 4 && (sz - 4) % KW_HDR_REC == 0) n = (size_t)(sz - 4) / KW_HDR_REC;
    }
    if (n > 0 && n <= s->count) {
        uint8_t rec[KW_HDR_REC];
        if (fseek(f, 4 + (long)(n - 1) * KW_HDR_REC, SEEK_SET) != 0 ||
            fread(rec, 1, KW_HDR_REC, f) != KW_HDR_REC ||
            memcmp(rec + KW_HEADER_LEN, s->h[n - 1].hash, 32) != 0) n = 0;
    } else n = 0;
    fclose(f);
    return n;
}

int kw_headerstore_save(const kw_headerstore *s, const char *path)
{
    size_t have = save_prefix(s, path);

    FILE *f = fopen(path, have ? "ab" : "wb");
    if (!f) return 0;
    int ok = have ? 1 : fwrite(KW_HDR_MAGIC2, 1, 4, f) == 4;
    for (size_t i = have; i < s->count && ok; i++)
        ok = fwrite(s->h[i].raw, 1, KW_HEADER_LEN, f) == KW_HEADER_LEN &&
             fwrite(s->h[i].hash, 1, 32, f) == 32;
    if (fclose(f) != 0) ok = 0;
    return ok;
}

int kw_headerstore_load(kw_headerstore *s, const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 1;                         /* no cache is not an error */
    uint8_t magic[4];
    if (fread(magic, 1, 4, f) != 4) { fclose(f); return 0; }
    int v2 = memcmp(magic, KW_HDR_MAGIC2, 4) == 0;
    if (!v2 && memcmp(magic, KW_HDR_MAGIC1, 4) != 0) { fclose(f); return 0; }

    /* One buffered read per chunk rather than two freads per record, and the
       records are built where they will live rather than in a local and copied.
       At six million records the old shape cost 700ms with the file already in
       the page cache, against 73ms to read the same bytes: stdio calls and then
       memory traffic, both paid by every command before it speaks to a peer. */
    size_t recl = v2 ? KW_HDR_REC : KW_HEADER_LEN;

    /* Size the array from the file so the growth is one allocation rather than a
       doubling sequence over six million appends. A wrong length here costs only
       a reallocation later: the loop still bounds itself by what it reads. */
    long end = -1;
    if (fseek(f, 0, SEEK_END) == 0) end = ftell(f);
    if (fseek(f, 4, SEEK_SET) != 0) { fclose(f); return 0; }
    if (end > 4) {
        size_t want = s->count + ((size_t)(end - 4) / recl) + 1;
        if (want > s->cap) {
            kw_block_header *nh = (kw_block_header *)realloc(s->h, want * sizeof *nh);
            if (!nh) { fclose(f); return 0; }
            s->h = nh; s->cap = want;
        }
    }

    size_t chunk = recl * 4096;
    uint8_t *buf = (uint8_t *)malloc(chunk);
    if (!buf) { fclose(f); return 0; }

    int ok = 1;
    size_t have = 0;
    for (;;) {
        size_t got = fread(buf + have, 1, chunk - have, f);
        have += got;
        if (have == 0) break;                 /* clean end */

        size_t off = 0;
        while (have - off >= recl) {
            if (s->count == s->cap) {         /* only if the length lied */
                size_t nc = s->cap ? s->cap * 2 : 4096;
                kw_block_header *nh = (kw_block_header *)realloc(s->h, nc * sizeof *nh);
                if (!nh) { ok = 0; break; }
                s->h = nh; s->cap = nc;
            }
            kw_block_header *dst = &s->h[s->count];
            memcpy(dst->raw, buf + off, KW_HEADER_LEN);
            if (v2) memcpy(dst->hash, buf + off + KW_HEADER_LEN, 32);
            else    kw_hash256(dst->raw, KW_HEADER_LEN, dst->hash);
            /* the same link the append path enforces, done in place */
            if (s->count > 0 &&
                memcmp(kw_block_header_prev(dst), s->h[s->count - 1].hash, 32) != 0) {
                ok = 0; break;
            }
            s->count++;
            off += recl;
        }
        if (!ok) break;

        size_t left = have - off;             /* a record split across two reads */
        if (left) memmove(buf, buf + off, left);
        have = left;
        if (got == 0) { if (left) ok = 0; break; }   /* trailing partial record */
    }
    free(buf);
    fclose(f);
    return ok;
}

