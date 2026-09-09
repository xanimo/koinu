/* koinu.dog - BIP174 partially signed transactions
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "psbt.h"
#include "ec.h"
#include "mem.h"

#include <stdlib.h>
#include <string.h>

static const uint8_t KW_PSBT_MAGIC[5] = { 0x70, 0x73, 0x62, 0x74, 0xff };

/* global */
#define PSBT_GLOBAL_UNSIGNED_TX 0x00
/* per input */
#define PSBT_IN_NON_WITNESS_UTXO 0x00
#define PSBT_IN_WITNESS_UTXO     0x01
#define PSBT_IN_PARTIAL_SIG      0x02
#define PSBT_IN_SIGHASH_TYPE     0x03
#define PSBT_IN_REDEEM_SCRIPT    0x04
#define PSBT_IN_WITNESS_SCRIPT   0x05
#define PSBT_IN_FINAL_SCRIPTSIG  0x07
#define PSBT_IN_FINAL_WITNESS    0x08
/* per output */
#define PSBT_OUT_REDEEM_SCRIPT   0x00
#define PSBT_OUT_WITNESS_SCRIPT  0x01

void kw_psbt_init(kw_psbt *p)
{
    memset(p, 0, sizeof *p);
    kw_tx_init(&p->tx);
}

void kw_psbt_free(kw_psbt *p)
{
    for (size_t i = 0; i < KW_TX_MAX_IN; i++) free(p->in[i].utxo);
    memset(p, 0, sizeof *p);
}

int kw_psbt_create(kw_psbt *p, const kw_tx *tx)
{
    for (size_t i = 0; i < tx->nin; i++)
        if (tx->vin[i].scriptlen) return 0;      /* not an unsigned transaction */
    kw_psbt_init(p);
    p->tx = *tx;
    return 1;
}

const kw_tx *kw_psbt_unsigned_tx(const kw_psbt *p) { return &p->tx; }

int kw_psbt_set_redeem(kw_psbt *p, size_t index, const uint8_t *script, size_t len)
{
    if (index >= p->tx.nin || len > KW_PSBT_SCRIPT_MAX) return 0;
    memcpy(p->in[index].redeem, script, len);
    p->in[index].redeemlen = len;
    return 1;
}

int kw_psbt_set_utxo(kw_psbt *p, size_t index, const uint8_t *rawtx, size_t len)
{
    if (index >= p->tx.nin || !len) return 0;
    uint8_t *c = (uint8_t *)malloc(len);
    if (!c) return 0;
    memcpy(c, rawtx, len);
    free(p->in[index].utxo);
    p->in[index].utxo = c;
    p->in[index].utxolen = len;
    return 1;
}

int kw_psbt_sign(kw_psbt *p, size_t index, const uint8_t sk[32], uint32_t hashtype)
{
    if (index >= p->tx.nin) return 0;
    kw_psbt_in *in = &p->in[index];
    if (!in->redeemlen) return 0;                /* nothing to hash against */

    uint8_t pub[33];
    if (!kw_ec_pubkey(sk, pub)) return 0;

    uint8_t sig[KW_EC_SIG_DER_MAX + 1]; size_t siglen = sizeof sig;
    if (!kw_tx_signature(&p->tx, index, sk, in->redeem, in->redeemlen,
                         hashtype, sig, &siglen)) return 0;

    size_t slot = in->nsigs;
    for (size_t i = 0; i < in->nsigs; i++)
        if (memcmp(in->sigs[i].pubkey, pub, 33) == 0) { slot = i; break; }
    if (slot == in->nsigs) {
        if (in->nsigs == KW_PSBT_MAX_SIGS) return -1;
        in->nsigs++;
    }
    memcpy(in->sigs[slot].pubkey, pub, 33);
    memcpy(in->sigs[slot].sig, sig, siglen);
    in->sigs[slot].siglen = siglen;
    in->sighash = hashtype; in->has_sighash = 1;
    return 1;
}

int kw_psbt_get_sig(const kw_psbt *p, size_t index, size_t n,
                    uint8_t pubkey[33], uint8_t *sig, size_t *siglen)
{
    if (index >= p->tx.nin || n >= p->in[index].nsigs) return 0;
    const kw_psbt_sig *s = &p->in[index].sigs[n];
    if (*siglen < s->siglen) return 0;
    memcpy(pubkey, s->pubkey, 33);
    memcpy(sig, s->sig, s->siglen);
    *siglen = s->siglen;
    return 1;
}

int kw_psbt_combine(kw_psbt *dst, const kw_psbt *src)
{
    uint8_t a[32], b[32];
    if (!kw_tx_txid(&dst->tx, a) || !kw_tx_txid(&src->tx, b)) return 0;
    if (memcmp(a, b, 32) != 0) return 0;         /* different transactions */

    for (size_t i = 0; i < dst->tx.nin; i++) {
        const kw_psbt_in *s = &src->in[i];
        kw_psbt_in *d = &dst->in[i];
        if (!d->redeemlen && s->redeemlen) {
            memcpy(d->redeem, s->redeem, s->redeemlen); d->redeemlen = s->redeemlen;
        }
        if (!d->finallen && s->finallen) {
            memcpy(d->final, s->final, s->finallen); d->finallen = s->finallen;
        }
        if (!d->utxo && s->utxo && !kw_psbt_set_utxo(dst, i, s->utxo, s->utxolen)) return 0;
        if (!d->has_sighash && s->has_sighash) { d->sighash = s->sighash; d->has_sighash = 1; }
        for (size_t k = 0; k < s->nsigs; k++) {
            size_t slot = d->nsigs;
            for (size_t j = 0; j < d->nsigs; j++)
                if (memcmp(d->sigs[j].pubkey, s->sigs[k].pubkey, 33) == 0) { slot = j; break; }
            if (slot == d->nsigs) {
                if (d->nsigs == KW_PSBT_MAX_SIGS) return 0;
                d->sigs[d->nsigs++] = s->sigs[k];
            }
        }
    }
    for (size_t i = 0; i < dst->tx.nout; i++)
        if (!dst->out[i].redeemlen && src->out[i].redeemlen) {
            memcpy(dst->out[i].redeem, src->out[i].redeem, src->out[i].redeemlen);
            dst->out[i].redeemlen = src->out[i].redeemlen;
        }
    return 1;
}

int kw_psbt_finalize(kw_psbt *p, size_t index, const uint8_t *scriptsig, size_t len)
{
    if (index >= p->tx.nin || len > KW_TX_SCRIPT_MAX) return 0;
    memcpy(p->in[index].final, scriptsig, len);
    p->in[index].finallen = len;
    return 1;
}

int kw_psbt_extract(const kw_psbt *p, kw_tx *tx)
{
    for (size_t i = 0; i < p->tx.nin; i++)
        if (!p->in[i].finallen) return 0;
    *tx = p->tx;
    for (size_t i = 0; i < p->tx.nin; i++) {
        memcpy(tx->vin[i].script, p->in[i].final, p->in[i].finallen);
        tx->vin[i].scriptlen = p->in[i].finallen;
    }
    return 1;
}

/* ── writer ──────────────────────────────────────────────────── */
typedef struct { uint8_t *p; size_t cap, len; int ok; } wr;

static void w_bytes(wr *w, const void *b, size_t n)
{
    if (!w->ok || w->len + n > w->cap) { w->ok = 0; return; }
    memcpy(w->p + w->len, b, n); w->len += n;
}
static void w_varint(wr *w, uint64_t v)
{
    uint8_t b[9]; size_t n = 0;
    if (v < 0xfd) b[n++] = (uint8_t)v;
    else if (v <= 0xffff) { b[n++] = 0xfd; b[n++] = (uint8_t)v; b[n++] = (uint8_t)(v >> 8); }
    else if (v <= 0xffffffff) { b[n++] = 0xfe; for (int i = 0; i < 4; i++) b[n++] = (uint8_t)(v >> (8*i)); }
    else { b[n++] = 0xff; for (int i = 0; i < 8; i++) b[n++] = (uint8_t)(v >> (8*i)); }
    w_bytes(w, b, n);
}
/* one key-value pair: a keytype byte, optional key data, then the value */
static void w_kv(wr *w, uint8_t type, const uint8_t *keydata, size_t keylen,
                 const uint8_t *val, size_t vallen)
{
    w_varint(w, 1 + keylen);
    w_bytes(w, &type, 1);
    if (keylen) w_bytes(w, keydata, keylen);
    w_varint(w, vallen);
    w_bytes(w, val, vallen);
}

size_t kw_psbt_serialize(const kw_psbt *p, uint8_t *out, size_t outcap)
{
    wr w = { out, outcap, 0, 1 };
    w_bytes(&w, KW_PSBT_MAGIC, 5);

    uint8_t txbuf[16384];
    kw_tx unsigned_tx = p->tx;                   /* the global tx carries no scriptSigs */
    for (size_t i = 0; i < unsigned_tx.nin; i++) unsigned_tx.vin[i].scriptlen = 0;
    size_t txlen = kw_tx_serialize(&unsigned_tx, txbuf, sizeof txbuf);
    if (!txlen) return 0;
    w_kv(&w, PSBT_GLOBAL_UNSIGNED_TX, NULL, 0, txbuf, txlen);
    uint8_t sep = 0x00;
    w_bytes(&w, &sep, 1);

    for (size_t i = 0; i < p->tx.nin; i++) {
        const kw_psbt_in *in = &p->in[i];
        if (in->utxo) w_kv(&w, PSBT_IN_NON_WITNESS_UTXO, NULL, 0, in->utxo, in->utxolen);
        for (size_t k = 0; k < in->nsigs; k++)
            w_kv(&w, PSBT_IN_PARTIAL_SIG, in->sigs[k].pubkey, 33,
                 in->sigs[k].sig, in->sigs[k].siglen);
        if (in->has_sighash) {
            uint8_t v[4];
            for (int b = 0; b < 4; b++) v[b] = (uint8_t)(in->sighash >> (8*b));
            w_kv(&w, PSBT_IN_SIGHASH_TYPE, NULL, 0, v, 4);
        }
        if (in->redeemlen) w_kv(&w, PSBT_IN_REDEEM_SCRIPT, NULL, 0, in->redeem, in->redeemlen);
        if (in->finallen)  w_kv(&w, PSBT_IN_FINAL_SCRIPTSIG, NULL, 0, in->final, in->finallen);
        w_bytes(&w, &sep, 1);
    }
    for (size_t i = 0; i < p->tx.nout; i++) {
        if (p->out[i].redeemlen)
            w_kv(&w, PSBT_OUT_REDEEM_SCRIPT, NULL, 0, p->out[i].redeem, p->out[i].redeemlen);
        w_bytes(&w, &sep, 1);
    }
    return w.ok ? w.len : 0;
}

/* ── reader ──────────────────────────────────────────────────── */
typedef struct { const uint8_t *p; size_t len, off; int bad; } rd;

static uint64_t r_varint(rd *r)
{
    if (r->bad || r->off >= r->len) { r->bad = 1; return 0; }
    uint8_t pfx = r->p[r->off++];
    int n = pfx < 0xfd ? 0 : pfx == 0xfd ? 2 : pfx == 0xfe ? 4 : 8;
    if (!n) return pfx;
    if (r->off + (size_t)n > r->len) { r->bad = 1; return 0; }
    uint64_t v = 0;
    for (int i = 0; i < n; i++) v |= (uint64_t)r->p[r->off + i] << (8*i);
    r->off += (size_t)n;
    return v;
}

/* Read one key-value pair. Returns 0 at the map separator, 1 on a pair, -1 on
   a malformed one. Key and value point into the input. */
static int r_kv(rd *r, const uint8_t **key, size_t *keylen,
                const uint8_t **val, size_t *vallen)
{
    uint64_t kl = r_varint(r);
    if (r->bad) return -1;
    if (kl == 0) return 0;                       /* separator */
    if (kl > r->len - r->off) { r->bad = 1; return -1; }
    *key = r->p + r->off; *keylen = (size_t)kl;
    r->off += (size_t)kl;
    uint64_t vl = r_varint(r);
    if (r->bad || vl > r->len - r->off) { r->bad = 1; return -1; }
    *val = r->p + r->off; *vallen = (size_t)vl;
    r->off += (size_t)vl;
    return 1;
}

int kw_psbt_parse(const uint8_t *in, size_t len, kw_psbt *p)
{
    kw_psbt_init(p);
    rd r = { in, len, 0, 0 };
    if (len < 5 || memcmp(in, KW_PSBT_MAGIC, 5) != 0) return 0;
    r.off = 5;

    int have_tx = 0;
    for (;;) {
        const uint8_t *k, *v; size_t kl, vl;
        int got = r_kv(&r, &k, &kl, &v, &vl);
        if (got < 0) goto bad;
        if (got == 0) break;
        if (k[0] != PSBT_GLOBAL_UNSIGNED_TX || kl != 1 || have_tx) goto bad;
        if (kw_tx_parse(v, vl, &p->tx) != vl) goto bad;
        for (size_t i = 0; i < p->tx.nin; i++)
            if (p->tx.vin[i].scriptlen) goto bad;   /* must be unsigned */
        have_tx = 1;
    }
    if (!have_tx) goto bad;

    for (size_t i = 0; i < p->tx.nin; i++) {
        kw_psbt_in *ip = &p->in[i];
        for (;;) {
            const uint8_t *k, *v; size_t kl, vl;
            int got = r_kv(&r, &k, &kl, &v, &vl);
            if (got < 0) goto bad;
            if (got == 0) break;
            switch (k[0]) {
            case PSBT_IN_NON_WITNESS_UTXO:
                if (kl != 1 || ip->utxo || !kw_psbt_set_utxo(p, i, v, vl)) goto bad;
                break;
            case PSBT_IN_PARTIAL_SIG:
                if (kl != 34 || vl > sizeof ip->sigs[0].sig ||
                    ip->nsigs == KW_PSBT_MAX_SIGS) goto bad;
                for (size_t j = 0; j < ip->nsigs; j++)
                    if (memcmp(ip->sigs[j].pubkey, k + 1, 33) == 0) goto bad;   /* duplicate key */
                memcpy(ip->sigs[ip->nsigs].pubkey, k + 1, 33);
                memcpy(ip->sigs[ip->nsigs].sig, v, vl);
                ip->sigs[ip->nsigs].siglen = vl;
                ip->nsigs++;
                break;
            case PSBT_IN_SIGHASH_TYPE:
                if (kl != 1 || vl != 4 || ip->has_sighash) goto bad;
                ip->sighash = (uint32_t)v[0] | ((uint32_t)v[1] << 8) |
                              ((uint32_t)v[2] << 16) | ((uint32_t)v[3] << 24);
                ip->has_sighash = 1;
                break;
            case PSBT_IN_REDEEM_SCRIPT:
                if (kl != 1 || vl > KW_PSBT_SCRIPT_MAX || ip->redeemlen) goto bad;
                memcpy(ip->redeem, v, vl); ip->redeemlen = vl;
                break;
            case PSBT_IN_FINAL_SCRIPTSIG:
                if (kl != 1 || vl > KW_TX_SCRIPT_MAX || ip->finallen) goto bad;
                memcpy(ip->final, v, vl); ip->finallen = vl;
                break;
            default:
                goto bad;      /* segwit or unknown: refuse rather than drop it */
            }
        }
    }

    for (size_t i = 0; i < p->tx.nout; i++) {
        for (;;) {
            const uint8_t *k, *v; size_t kl, vl;
            int got = r_kv(&r, &k, &kl, &v, &vl);
            if (got < 0) goto bad;
            if (got == 0) break;
            if (k[0] != PSBT_OUT_REDEEM_SCRIPT || kl != 1 ||
                vl > KW_PSBT_SCRIPT_MAX || p->out[i].redeemlen) goto bad;
            memcpy(p->out[i].redeem, v, vl); p->out[i].redeemlen = vl;
        }
    }
    if (r.off != r.len) goto bad;                /* trailing bytes */
    return 1;
bad:
    kw_psbt_free(p);
    return 0;
}
