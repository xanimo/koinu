/* koinu.dog - block headers, getheaders/headers, and the header chain
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "headers.h"
#include "sha2.h"
#include "mem.h"

#include <stdlib.h>
#include <string.h>

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

int kw_msg_headers_parse(const uint8_t *in, size_t len,
                         kw_block_header *out, size_t maxout, size_t *nout)
{
    R r = { in, len, 0, 0 };
    uint64_t count = r_varint(&r);
    if (r.bad) return 0;
    if (count > maxout || count > KW_MAX_HEADERS) return 0;

    for (uint64_t i = 0; i < count; i++) {
        if (r.off + KW_HEADER_LEN > r.len) return 0;
        if (rd_le32(r.p + r.off) & KW_BLOCK_VERSION_AUXPOW) return -1;  /* auxpow: not yet */
        kw_block_header_parse(r.p + r.off, KW_HEADER_LEN, &out[i]);
        r.off += KW_HEADER_LEN;
        (void)r_varint(&r);            /* tx count, 0 in a headers message */
        if (r.bad) return 0;
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

void kw_headerstore_free(kw_headerstore *s)
{
    free(s->h);
    s->h = NULL; s->count = s->cap = 0;
}
