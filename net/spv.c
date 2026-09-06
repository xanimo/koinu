/* koinu.dog - classic SPV: full-block download and local scan
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "spv.h"
#include "tx.h"

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

int kw_block_scan(const uint8_t *msg, size_t len,
                  kw_utxoset *us, const kw_watchset *ws, uint32_t height)
{
    if (len < KW_HEADER_LEN + 1) return 0;
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

/* ── live driver ─────────────────────────────────────────────── */
int kw_spv_fetch_block(kw_peer *p, const uint8_t hash[32],
                       kw_utxoset *us, const kw_watchset *ws, uint32_t height)
{
    uint8_t body[64];
    size_t bn = kw_msg_getdata_blocks_build((const uint8_t (*)[32])hash, 1, body, sizeof body);
    if (!bn || !kw_peer_send(p, "getdata", body, bn)) return 0;

    char cmd[13]; const uint8_t *pl = NULL; size_t pn = 0;
    int got = 0;
    while (kw_peer_recv(p, cmd, &pl, &pn) == 1) {
        if (!strcmp(cmd, "block")) { got = 1; break; }
        if (!strcmp(cmd, "ping")) kw_peer_send(p, "pong", pl, pn);
    }
    if (!got) return 0;

    /* the block we asked for, not some other one */
    kw_block_header hdr;
    if (!kw_block_header_parse(pl, pn, &hdr) || memcmp(hdr.hash, hash, 32) != 0) return 0;

    return kw_block_scan(pl, pn, us, ws, height);
}

long kw_spv_sync_blocks(kw_peer *p, const kw_headerstore *s,
                        kw_utxoset *us, const kw_watchset *ws, uint32_t base_height)
{
    long scanned = 0;
    for (size_t h = 0; h < s->count; h++) {
        if (!kw_spv_fetch_block(p, s->h[h].hash, us, ws, base_height + (uint32_t)h)) return -1;
        scanned++;
    }
    return scanned;
}
