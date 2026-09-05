/* dogewallet - transaction building, legacy sighash, P2PKH signing
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

void dw_tx_init(dw_tx *tx)
{
    memset(tx, 0, sizeof *tx);
    tx->version = 1;
    tx->locktime = 0;
}

int dw_tx_add_input(dw_tx *tx, const char *txid_hex, uint32_t vout)
{
    if (tx->nin >= DW_TX_MAX_IN) return 0;
    if (strlen(txid_hex) != 64) return 0;
    uint8_t disp[32];
    if (!dw_hex_decode(txid_hex, 64, disp, 32)) return 0;

    dw_txin *in = &tx->vin[tx->nin];
    memset(in, 0, sizeof *in);
    for (int i = 0; i < 32; i++) in->prevout[i] = disp[31 - i];   /* display -> internal */
    in->vout = vout;
    in->sequence = 0xffffffffu;
    in->scriptlen = 0;
    tx->nin++;
    return 1;
}

int dw_tx_add_output(dw_tx *tx, uint64_t value, const uint8_t *script, size_t scriptlen)
{
    if (tx->nout >= DW_TX_MAX_OUT || scriptlen > DW_TX_SCRIPT_MAX) return 0;
    dw_txout *o = &tx->vout[tx->nout];
    o->value = value;
    memcpy(o->script, script, scriptlen);
    o->scriptlen = scriptlen;
    tx->nout++;
    return 1;
}

int dw_tx_add_output_p2pkh(dw_tx *tx, uint64_t value, const uint8_t hash160[20])
{
    uint8_t spk[25];
    spk[0] = 0x76; spk[1] = 0xa9; spk[2] = 0x14;
    memcpy(spk + 3, hash160, 20);
    spk[23] = 0x88; spk[24] = 0xac;
    return dw_tx_add_output(tx, value, spk, sizeof spk);
}

/* Serialize. When sig_index >= 0, write it in signing form: input sig_index
   carries (subscript) as its scriptSig and every other input an empty one. */
static size_t serialize_core(const dw_tx *tx, long sig_index,
                             const uint8_t *subscript, size_t sublen,
                             uint8_t *out, size_t outcap)
{
    wr w = { out, outcap, 0, 1 };
    w_u32(&w, tx->version);
    w_varint(&w, tx->nin);
    for (size_t i = 0; i < tx->nin; i++) {
        const dw_txin *in = &tx->vin[i];
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

size_t dw_tx_serialize(const dw_tx *tx, uint8_t *out, size_t outcap)
{
    return serialize_core(tx, -1, NULL, 0, out, outcap);
}

int dw_tx_sighash(const dw_tx *tx, size_t index,
                  const uint8_t *subscript, size_t subscriptlen,
                  uint32_t hashtype, uint8_t out[32])
{
    if (index >= tx->nin || hashtype != DW_SIGHASH_ALL) return 0;
    uint8_t buf[16384];
    size_t n = serialize_core(tx, (long)index, subscript, subscriptlen, buf, sizeof buf - 4);
    if (!n) return 0;
    buf[n++] = (uint8_t)hashtype; buf[n++] = 0; buf[n++] = 0; buf[n++] = 0;   /* hashtype LE32 */
    dw_hash256(buf, n, out);
    dw_secure_zero(buf, sizeof buf);
    return 1;
}

int dw_tx_sign_p2pkh(dw_tx *tx, size_t index, const uint8_t sk[32],
                     const uint8_t *prev_spk, size_t prev_spk_len)
{
    if (index >= tx->nin) return 0;

    uint8_t hash[32];
    if (!dw_tx_sighash(tx, index, prev_spk, prev_spk_len, DW_SIGHASH_ALL, hash)) return 0;

    uint8_t der[DW_EC_SIG_DER_MAX];
    size_t derlen = 0;
    if (!dw_ec_sign(sk, hash, der, &derlen)) return 0;
    if (derlen + 1 > 75) return 0;                 /* must be a single-byte push */

    uint8_t pub[33];
    if (!dw_ec_pubkey(sk, pub)) return 0;

    /* scriptSig = <sig||SIGHASH_ALL> <pubkey> */
    dw_txin *in = &tx->vin[index];
    size_t k = 0;
    in->script[k++] = (uint8_t)(derlen + 1);
    memcpy(in->script + k, der, derlen); k += derlen;
    in->script[k++] = DW_SIGHASH_ALL;
    in->script[k++] = 33;
    memcpy(in->script + k, pub, 33); k += 33;
    in->scriptlen = k;

    dw_secure_zero(hash, sizeof hash);
    return 1;
}

int dw_tx_txid(const dw_tx *tx, uint8_t out[32])
{
    uint8_t buf[16384];
    size_t n = dw_tx_serialize(tx, buf, sizeof buf);
    if (!n) return 0;
    dw_hash256(buf, n, out);
    dw_secure_zero(buf, sizeof buf);
    return 1;
}
