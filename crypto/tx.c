/* koinu.dog - transaction building, legacy sighash, P2PKH signing
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "tx.h"
#include "sha2.h"
#include "ec.h"
#include "mem.h"
#include "hex.h"

#include <string.h>

/* bounds-checked writer */
typedef struct { uint8_t *p; size_t cap, len; int ok; } wr;

static void w_bytes(wr *w, const void *b, size_t n)
{
    if (!w->ok || w->len + n > w->cap) { w->ok = 0; return; }
    memcpy(w->p + w->len, b, n);
    w->len += n;
}
static void w_u8(wr *w, uint8_t v)  { w_bytes(w, &v, 1); }
static void w_u32(wr *w, uint32_t v){ uint8_t b[4]; for (int i=0;i<4;i++) b[i]=(uint8_t)(v>>(8*i)); w_bytes(w,b,4); }
static void w_u64(wr *w, uint64_t v){ uint8_t b[8]; for (int i=0;i<8;i++) b[i]=(uint8_t)(v>>(8*i)); w_bytes(w,b,8); }
static void w_varint(wr *w, uint64_t v)
{
    if (v < 0xfd) { w_u8(w, (uint8_t)v); }
    else if (v <= 0xffff) { w_u8(w, 0xfd); w_u8(w,(uint8_t)v); w_u8(w,(uint8_t)(v>>8)); }
    else if (v <= 0xffffffffULL) { w_u8(w, 0xfe); w_u32(w,(uint32_t)v); }
    else { w_u8(w, 0xff); w_u64(w, v); }
}

void kw_tx_init(kw_tx *tx)
{
    memset(tx, 0, sizeof *tx);
    tx->version = 1;
    tx->locktime = 0;
}

int kw_tx_add_input(kw_tx *tx, const char *txid_hex, uint32_t vout)
{
    if (tx->nin >= KW_TX_MAX_IN) return 0;
    if (strlen(txid_hex) != 64) return 0;
    uint8_t disp[32];
    if (!kw_hex_decode(txid_hex, 64, disp, 32)) return 0;

    kw_txin *in = &tx->vin[tx->nin];
    memset(in, 0, sizeof *in);
    for (int i = 0; i < 32; i++) in->prevout[i] = disp[31 - i];   /* display -> internal */
    in->vout = vout;
    in->sequence = 0xffffffffu;
    in->scriptlen = 0;
    tx->nin++;
    return 1;
}

int kw_tx_add_output(kw_tx *tx, uint64_t value, const uint8_t *script, size_t scriptlen)
{
    if (tx->nout >= KW_TX_MAX_OUT || scriptlen > KW_TX_SCRIPT_MAX) return 0;
    kw_txout *o = &tx->vout[tx->nout];
    o->value = value;
    memcpy(o->script, script, scriptlen);
    o->scriptlen = scriptlen;
    tx->nout++;
    return 1;
}

int kw_tx_add_output_p2pkh(kw_tx *tx, uint64_t value, const uint8_t hash160[20])
{
    uint8_t spk[25];
    spk[0] = 0x76; spk[1] = 0xa9; spk[2] = 0x14;
    memcpy(spk + 3, hash160, 20);
    spk[23] = 0x88; spk[24] = 0xac;
    return kw_tx_add_output(tx, value, spk, sizeof spk);
}

/* Serialize. When sig_index >= 0, write it in signing form: input sig_index
   carries (subscript) as its scriptSig and every other input an empty one. */
static size_t serialize_core(const kw_tx *tx, long sig_index,
                             const uint8_t *subscript, size_t sublen,
                             uint8_t *out, size_t outcap)
{
    wr w = { out, outcap, 0, 1 };
    w_u32(&w, tx->version);
    w_varint(&w, tx->nin);
    for (size_t i = 0; i < tx->nin; i++) {
        const kw_txin *in = &tx->vin[i];
        w_bytes(&w, in->prevout, 32);
        w_u32(&w, in->vout);
        if (sig_index < 0) {
            w_varint(&w, in->scriptlen);
            w_bytes(&w, in->script, in->scriptlen);
        } else if ((size_t)sig_index == i) {
            w_varint(&w, sublen);
            w_bytes(&w, subscript, sublen);
        } else {
            w_varint(&w, 0);
        }
        w_u32(&w, in->sequence);
    }
    w_varint(&w, tx->nout);
    for (size_t i = 0; i < tx->nout; i++) {
        w_u64(&w, tx->vout[i].value);
        w_varint(&w, tx->vout[i].scriptlen);
        w_bytes(&w, tx->vout[i].script, tx->vout[i].scriptlen);
    }
    w_u32(&w, tx->locktime);
    return w.ok ? w.len : 0;
}

size_t kw_tx_serialize(const kw_tx *tx, uint8_t *out, size_t outcap)
{
    return serialize_core(tx, -1, NULL, 0, out, outcap);
}

int kw_tx_sighash(const kw_tx *tx, size_t index,
                  const uint8_t *subscript, size_t subscriptlen,
                  uint32_t hashtype, uint8_t out[32])
{
    if (index >= tx->nin || hashtype != KW_SIGHASH_ALL) return 0;
    uint8_t buf[16384];
    size_t n = serialize_core(tx, (long)index, subscript, subscriptlen, buf, sizeof buf - 4);
    if (!n) return 0;
    buf[n++] = (uint8_t)hashtype; buf[n++] = 0; buf[n++] = 0; buf[n++] = 0;   /* hashtype LE32 */
    kw_hash256(buf, n, out);
    kw_secure_zero(buf, sizeof buf);
    return 1;
}

int kw_tx_sign_p2pkh(kw_tx *tx, size_t index, const uint8_t sk[32],
                     const uint8_t *prev_spk, size_t prev_spk_len)
{
    if (index >= tx->nin) return 0;

    uint8_t hash[32];
    if (!kw_tx_sighash(tx, index, prev_spk, prev_spk_len, KW_SIGHASH_ALL, hash)) return 0;

    uint8_t der[KW_EC_SIG_DER_MAX];
    size_t derlen = 0;
    if (!kw_ec_sign(sk, hash, der, &derlen)) return 0;
    if (derlen + 1 > 75) return 0;                 /* must be a single-byte push */

    uint8_t pub[33];
    if (!kw_ec_pubkey(sk, pub)) return 0;

    /* scriptSig = <sig||SIGHASH_ALL> <pubkey> */
    kw_txin *in = &tx->vin[index];
    size_t k = 0;
    in->script[k++] = (uint8_t)(derlen + 1);
    memcpy(in->script + k, der, derlen); k += derlen;
    in->script[k++] = KW_SIGHASH_ALL;
    in->script[k++] = 33;
    memcpy(in->script + k, pub, 33); k += 33;
    in->scriptlen = k;

    kw_secure_zero(hash, sizeof hash);
    return 1;
}

int kw_tx_txid(const kw_tx *tx, uint8_t out[32])
{
    uint8_t buf[16384];
    size_t n = kw_tx_serialize(tx, buf, sizeof buf);
    if (!n) return 0;
    kw_hash256(buf, n, out);
    kw_secure_zero(buf, sizeof buf);
    return 1;
}

/* ── bounds-checked reader for scanning ──────────────────────── */
typedef struct { const uint8_t *p; size_t len, off; int bad; } rd;

static uint64_t rd_le(rd *r, int n)
{
    if (r->bad || r->off + (size_t)n > r->len) { r->bad = 1; return 0; }
    uint64_t v = 0;
    for (int i = 0; i < n; i++) v |= (uint64_t)r->p[r->off + i] << (8 * i);
    r->off += (size_t)n;
    return v;
}
static uint64_t rd_varint(rd *r)
{
    if (r->bad || r->off >= r->len) { r->bad = 1; return 0; }
    uint8_t pfx = r->p[r->off++];
    if (pfx < 0xfd) return pfx;
    return rd_le(r, pfx == 0xfd ? 2 : pfx == 0xfe ? 4 : 8);
}
static void rd_skip(rd *r, uint64_t n)
{
    if (r->bad || n > (uint64_t)(r->len - r->off)) { r->bad = 1; return; }
    r->off += (size_t)n;
}
/* a count can't exceed the bytes left, which also bounds its loop */
static uint64_t rd_count(rd *r)
{
    uint64_t v = rd_varint(r);
    if (v > (uint64_t)(r->len - r->off)) r->bad = 1;
    return v;
}

/* One pass over a legacy tx. When (fire), reports inputs and outputs; (txid) is
   only used for the output callback. */
static void tx_walk(rd *r, int fire, const uint8_t txid[32],
                    void (*on_in)(void *, const uint8_t[32], uint32_t),
                    void (*on_out)(void *, const uint8_t[32], uint32_t, uint64_t,
                                   const uint8_t *, size_t),
                    void *ctx)
{
    rd_skip(r, 4);                            /* version */
    uint64_t nin = rd_count(r);
    for (uint64_t i = 0; i < nin && !r->bad; i++) {
        if (r->off + 36 > r->len) { r->bad = 1; break; }
        const uint8_t *prev = r->p + r->off;
        r->off += 32;
        uint32_t vout = (uint32_t)rd_le(r, 4);
        if (fire && on_in) on_in(ctx, prev, vout);
        rd_skip(r, rd_count(r));             /* scriptSig */
        rd_skip(r, 4);                        /* sequence */
    }
    uint64_t nout = rd_count(r);
    for (uint64_t i = 0; i < nout && !r->bad; i++) {
        uint64_t value = rd_le(r, 8);
        uint64_t sl = rd_count(r);
        if (r->bad) break;
        const uint8_t *spk = r->p + r->off;
        rd_skip(r, sl);
        if (fire && on_out && !r->bad) on_out(ctx, txid, (uint32_t)i, value, spk, (size_t)sl);
    }
    rd_skip(r, 4);                            /* locktime */
}

size_t kw_tx_scan(const uint8_t *raw, size_t len, uint8_t txid[32],
                  void (*on_input)(void *, const uint8_t[32], uint32_t),
                  void (*on_output)(void *, const uint8_t[32], uint32_t, uint64_t,
                                    const uint8_t *, size_t),
                  void *ctx)
{
    rd r1 = { raw, len, 0, 0 };
    tx_walk(&r1, 0, NULL, NULL, NULL, NULL);  /* length + validity pass */
    if (r1.bad) return 0;
    size_t consumed = r1.off;

    uint8_t id[32];
    kw_hash256(raw, consumed, id);
    if (txid) memcpy(txid, id, 32);

    rd r2 = { raw, consumed, 0, 0 };
    tx_walk(&r2, 1, id, on_input, on_output, ctx);  /* reporting pass */
    return consumed;
}
