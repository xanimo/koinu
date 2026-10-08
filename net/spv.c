/* koinu.dog - classic SPV: full-block download and local scan
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "spv.h"
#include "sha2.h"
#include "tx.h"

#include <stdlib.h>
#include <string.h>

/* ── getdata writer ──────────────────────────────────────────── */
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

size_t kw_msg_getdata_blocks_build(const uint8_t (*hashes)[32], size_t n,
                                   uint8_t *out, size_t outcap)
{
    W w = { out, outcap, 0, 1 };
    w_varint(&w, n);
    for (size_t i = 0; i < n; i++) { w_le32(&w, KW_INV_MSG_BLOCK); w_bytes(&w, hashes[i], 32); }
    return w.ok ? w.len : 0;
}

/* ── block scan ──────────────────────────────────────────────── */
static uint64_t rd_varint(const uint8_t *p, size_t len, size_t *off, int *bad)
{
    if (*off >= len) { *bad = 1; return 0; }
    uint8_t pfx = p[(*off)++];
    int n = 0;
    if (pfx < 0xfd) return pfx;
    else if (pfx == 0xfd) n = 2;
    else if (pfx == 0xfe) n = 4;
    else n = 8;
    if (*off + (size_t)n > len) { *bad = 1; return 0; }
    uint64_t v = 0;
    for (int i = 0; i < n; i++) v |= (uint64_t)p[*off + i] << (8 * i);
    *off += (size_t)n;
    return v;
}

/* A block cannot hold more transactions than this and stay inside the frame limit;
   the bound is here so a claimed count cannot ask for an arbitrary allocation. */
#define KW_BLOCK_MAX_TX (1u << 17)

/* The first input of the first transaction: a coinbase spends nothing, so its
   prevout is 32 zero bytes with vout 0xffffffff. */
struct cb_ctx { int seen; int coinbase; };

static void cb_on_input(void *v, const uint8_t prev[32], uint32_t vout)
{
    struct cb_ctx *c = (struct cb_ctx *)v;
    if (c->seen) { c->coinbase = 0; return; }   /* a coinbase has exactly one */
    c->seen = 1;
    static const uint8_t zero[32] = { 0 };
    c->coinbase = (vout == 0xffffffffu && memcmp(prev, zero, 32) == 0);
}

int kw_block_merkle_ok(const uint8_t *msg, size_t len)
{
    if (len < KW_HEADER_LEN + 1) return 0;
    uint32_t version = (uint32_t)msg[0] | (uint32_t)msg[1] << 8 |
                       (uint32_t)msg[2] << 16 | (uint32_t)msg[3] << 24;
    size_t off = KW_HEADER_LEN;
    if ((version & KW_BLOCK_VERSION_AUXPOW) && !kw_auxpow_skip(msg, len, &off)) return 0;

    int bad = 0;
    uint64_t ntx = rd_varint(msg, len, &off, &bad);
    if (bad || ntx == 0 || ntx > KW_BLOCK_MAX_TX || ntx > (uint64_t)(len - off)) return 0;

    uint8_t (*h)[32] = (uint8_t (*)[32])malloc((size_t)ntx * 32);
    if (!h) return 0;

    size_t n = 0;
    for (uint64_t i = 0; i < ntx; i++) {
        struct cb_ctx first = { 0, 0 };
        size_t consumed = kw_tx_scan(msg + off, len - off, NULL,
                                     i == 0 ? cb_on_input : NULL, NULL, &first);
        if (!consumed) { free(h); return 0; }
        /* A 64-byte transaction is the one length that can be read as a pair of
           txids, which is how a single blob stands in for two leaves under a root
           that commits to neither. The duplicate-pair check above does not see it,
           because the two halves are not a pair at this level. No transaction on
           this chain is 64 bytes: the shortest legacy form is 60 and needs empty
           scripts to get there. */
        if (consumed == 64) { free(h); return 0; }
        /* and the first transaction in a block is a coinbase, which a stand-in
           would have to grind a null prevout inside a txid to satisfy */
        if (i == 0 && !first.coinbase) { free(h); return 0; }
        kw_hash256(msg + off, consumed, h[n++]);
        off += consumed;
    }

    while (n > 1) {
        /* an identical adjacent pair means the tree could have been built from a
           different list, so the root proves nothing about which one */
        for (size_t i = 0; i + 1 < n; i += 2)
            if (memcmp(h[i], h[i + 1], 32) == 0) { free(h); return 0; }
        /* An odd node pairs with itself. Writing the copy into h[n] would be one past
           the allocation when n is the transaction count, so it is read twice instead
           of appended. */
        size_t w = 0;
        for (size_t i = 0; i < n; i += 2, w++) {
            uint8_t cat[64];
            memcpy(cat, h[i], 32);
            memcpy(cat + 32, (i + 1 < n) ? h[i + 1] : h[i], 32);
            kw_hash256(cat, 64, h[w]);
        }
        n = w;
    }

    int ok = memcmp(h[0], msg + 36, 32) == 0;             /* hashMerkleRoot */
    free(h);
    return ok;
}

int kw_block_scan(const uint8_t *msg, size_t len,
                  kw_utxoset *us, kw_watchset *ws, uint32_t height)
{
    if (len < KW_HEADER_LEN + 1) return 0;
    if (!kw_block_merkle_ok(msg, len)) return 0;   /* the body its header commits to */
    uint32_t version = (uint32_t)msg[0] | (uint32_t)msg[1] << 8 |
                       (uint32_t)msg[2] << 16 | (uint32_t)msg[3] << 24;
    size_t off = KW_HEADER_LEN;
    /* an AuxPoW block carries merged-mining data between the header and the tx
       count, exactly as the headers stream does */
    if ((version & KW_BLOCK_VERSION_AUXPOW) && !kw_auxpow_skip(msg, len, &off)) return 0;
    int bad = 0;
    uint64_t ntx = rd_varint(msg, len, &off, &bad);
    if (bad || ntx > (uint64_t)len) return 0;      /* each tx is >= 1 byte */

    for (uint64_t i = 0; i < ntx; i++) {
        size_t consumed = kw_tx_scan(msg + off, len - off, NULL, NULL, NULL, NULL);
        if (!consumed) return 0;
        if (!kw_utxoset_apply_tx(us, ws, msg + off, consumed, height)) return 0;
        off += consumed;
    }
    return 1;
}

/* ── targeted outpoint scan ──────────────────────────────────── */
struct fo_ctx {
    const uint8_t *txid; uint32_t vout;
    const uint8_t *spk; size_t spklen;
    int created; uint64_t value; int spent;
};

static void fo_on_input(void *v, const uint8_t prev[32], uint32_t vout)
{
    struct fo_ctx *c = (struct fo_ctx *)v;
    if (vout == c->vout && memcmp(prev, c->txid, 32) == 0) c->spent = 1;
}
static void fo_on_output(void *v, const uint8_t txid[32], uint32_t index,
                         uint64_t value, const uint8_t *spk, size_t spklen)
{
    struct fo_ctx *c = (struct fo_ctx *)v;
    if (index != c->vout || memcmp(txid, c->txid, 32) != 0) return;
    /* Who it pays decides the answer, not where it sits. Without this the payer
       broadcasts a real transaction paying themselves, hands over TXID:0, and
       the merchant is told their own script was funded. */
    if (spklen != c->spklen || memcmp(spk, c->spk, spklen) != 0) return;
    c->created = 1; c->value = value;
}

int kw_block_find_outpoint(const uint8_t *msg, size_t len,
                           const uint8_t txid[32], uint32_t vout,
                           const uint8_t *spk, size_t spklen, kw_outpoint_status *st)
{
    if (!spk || !spklen) return 0;
    if (len < KW_HEADER_LEN + 1) return 0;
    /* This answer is what a merchant ships against, so the body has to be the one the
       header commits to before any output in it is reported as present. */
    if (!kw_block_merkle_ok(msg, len)) return 0;
    uint32_t version = (uint32_t)msg[0] | (uint32_t)msg[1] << 8 |
                       (uint32_t)msg[2] << 16 | (uint32_t)msg[3] << 24;
    size_t off = KW_HEADER_LEN;
    if ((version & KW_BLOCK_VERSION_AUXPOW) && !kw_auxpow_skip(msg, len, &off)) return 0;
    int bad = 0;
    uint64_t ntx = rd_varint(msg, len, &off, &bad);
    if (bad || ntx > (uint64_t)len) return 0;

    struct fo_ctx c = { txid, vout, spk, spklen, 0, 0, 0 };
    for (uint64_t i = 0; i < ntx; i++) {
        size_t consumed = kw_tx_scan(msg + off, len - off, NULL, fo_on_input, fo_on_output, &c);
        if (!consumed) return 0;
        off += consumed;
    }
    st->created = c.created; st->created_value = c.value; st->spent = c.spent;
    return 1;
}

/* ── live driver ─────────────────────────────────────────────── */
int kw_spv_get_block(kw_peer *p, const uint8_t hash[32],
                     const uint8_t **payload, size_t *plen)
{
    uint8_t body[64];
    size_t bn = kw_msg_getdata_blocks_build((const uint8_t (*)[32])hash, 1, body, sizeof body);
    if (!bn || !kw_peer_send(p, "getdata", body, bn)) return 0;

    const uint8_t *pl = NULL; size_t pn = 0;
    if (!kw_peer_wait(p, "block", &pl, &pn)) return 0;

    /* the block we asked for, not some other one. The body is not checked against
       the header here: every function that reads one does that itself, and doing
       it twice per block doubles the hashing a scan spends most of its time on. */
    kw_block_header hdr;
    if (!kw_block_header_parse(pl, pn, &hdr) || memcmp(hdr.hash, hash, 32) != 0) return 0;
    *payload = pl; *plen = pn;
    return 1;
}

int kw_spv_fetch_block(kw_peer *p, const uint8_t hash[32],
                       kw_utxoset *us, kw_watchset *ws, uint32_t height)
{
    const uint8_t *pl = NULL; size_t pn = 0;
    if (!kw_spv_get_block(p, hash, &pl, &pn)) return 0;
    return kw_block_scan(pl, pn, us, ws, height);
}

long kw_spv_sync_blocks(kw_peer *p, const kw_headerstore *s,
                        kw_utxoset *us, kw_watchset *ws, uint32_t base_height)
{
    long scanned = 0;
    for (size_t h = 0; h < s->count; h++) {
        if (!kw_spv_fetch_block(p, s->h[h].hash, us, ws, base_height + (uint32_t)h)) return -1;
        scanned++;
    }
    return scanned;
}
