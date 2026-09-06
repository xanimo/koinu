/* koinu.dog - watched scripts and the tracked UTXO set
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "utxo.h"
#include "tx.h"

#include <stdlib.h>
#include <string.h>

/* ── watch set ───────────────────────────────────────────────── */
int kw_watchset_init(kw_watchset *ws)
{
    ws->count = 0;
    ws->cap = 8;
    ws->w = (kw_watch *)malloc(ws->cap * sizeof *ws->w);
    return ws->w != NULL;
}

int kw_watchset_add(kw_watchset *ws, const uint8_t *spk, size_t len)
{
    if (len == 0 || len > KW_SPK_MAX) return 0;
    if (kw_watchset_has(ws, spk, len)) return 1;
    if (ws->count == ws->cap) {
        size_t nc = ws->cap * 2;
        kw_watch *nw = (kw_watch *)realloc(ws->w, nc * sizeof *nw);
        if (!nw) return 0;
        ws->w = nw; ws->cap = nc;
    }
    memcpy(ws->w[ws->count].spk, spk, len);
    ws->w[ws->count].len = len;
    ws->count++;
    return 1;
}

int kw_watchset_has(const kw_watchset *ws, const uint8_t *spk, size_t len)
{
    for (size_t i = 0; i < ws->count; i++)
        if (ws->w[i].len == len && memcmp(ws->w[i].spk, spk, len) == 0) return 1;
    return 0;
}

void kw_watchset_free(kw_watchset *ws)
{
    free(ws->w);
    ws->w = NULL; ws->count = ws->cap = 0;
}

/* ── UTXO set ────────────────────────────────────────────────── */
int kw_utxoset_init(kw_utxoset *us)
{
    us->count = 0;
    us->cap = 16;
    us->u = (kw_utxo *)malloc(us->cap * sizeof *us->u);
    return us->u != NULL;
}

void kw_utxoset_free(kw_utxoset *us)
{
    free(us->u);
    us->u = NULL; us->count = us->cap = 0;
}

size_t kw_utxoset_count(const kw_utxoset *us) { return us->count; }

uint64_t kw_utxoset_balance(const kw_utxoset *us)
{
    uint64_t sum = 0;
    for (size_t i = 0; i < us->count; i++) sum += us->u[i].value;
    return sum;
}

static void utxo_remove(kw_utxoset *us, const uint8_t txid[32], uint32_t vout)
{
    for (size_t i = 0; i < us->count; i++) {
        if (us->u[i].vout == vout && memcmp(us->u[i].txid, txid, 32) == 0) {
            us->u[i] = us->u[us->count - 1];   /* swap-remove; order does not matter */
            us->count--;
            return;
        }
    }
}

static int utxo_add(kw_utxoset *us, const uint8_t txid[32], uint32_t vout,
                    uint64_t value, uint32_t height, const uint8_t *spk, size_t spklen)
{
    if (spklen > KW_SPK_MAX) return 0;
    if (us->count == us->cap) {
        size_t nc = us->cap * 2;
        kw_utxo *nu = (kw_utxo *)realloc(us->u, nc * sizeof *nu);
        if (!nu) return 0;
        us->u = nu; us->cap = nc;
    }
    kw_utxo *e = &us->u[us->count++];
    memcpy(e->txid, txid, 32);
    e->vout = vout;
    e->value = value;
    e->height = height;
    memcpy(e->spk, spk, spklen);
    e->spklen = spklen;
    return 1;
}

struct apply_ctx {
    kw_utxoset        *us;
    const kw_watchset *ws;
    uint32_t           height;
    int                ok;
};

static void on_input(void *vc, const uint8_t prev[32], uint32_t vout)
{
    struct apply_ctx *c = (struct apply_ctx *)vc;
    utxo_remove(c->us, prev, vout);
}

static void on_output(void *vc, const uint8_t txid[32], uint32_t index,
                      uint64_t value, const uint8_t *spk, size_t spklen)
{
    struct apply_ctx *c = (struct apply_ctx *)vc;
    if (spklen <= KW_SPK_MAX && kw_watchset_has(c->ws, spk, spklen))
        if (!utxo_add(c->us, txid, index, value, c->height, spk, spklen)) c->ok = 0;
}

int kw_utxoset_apply_tx(kw_utxoset *us, const kw_watchset *ws,
                        const uint8_t *rawtx, size_t len, uint32_t height)
{
    struct apply_ctx c = { us, ws, height, 1 };
    if (kw_tx_scan(rawtx, len, NULL, on_input, on_output, &c) == 0) return 0;
    return c.ok;
}
