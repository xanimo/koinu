/* koinu.dog - watched scripts and the tracked UTXO set
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * A watch set holds the scriptPubKeys the wallet owns. Applying a transaction
 * removes any of our UTXOs it spends and adds any output paying a watched
 * script, so the UTXO set and its balance follow the chain the client syncs. */

#ifndef KOINU_UTXO_H
#define KOINU_UTXO_H

#include <stddef.h>
#include <stdint.h>

#define KW_SPK_MAX 64        /* p2pkh is 25, p2sh 23; a watched script fits here */

/* ── watch set ───────────────────────────────────────────────── */
typedef struct { uint8_t spk[KW_SPK_MAX]; size_t len; } kw_watch;
typedef struct { kw_watch *w; size_t count, cap; } kw_watchset;

int  kw_watchset_init(kw_watchset *ws);
/* Add a scriptPubKey to watch. Returns 1, or 0 if too long or out of memory. */
int  kw_watchset_add(kw_watchset *ws, const uint8_t *spk, size_t len);
int  kw_watchset_has(const kw_watchset *ws, const uint8_t *spk, size_t len);
void kw_watchset_free(kw_watchset *ws);

/* ── UTXO set ────────────────────────────────────────────────── */
typedef struct {
    uint8_t  txid[32];               /* internal byte order */
    uint32_t vout;
    uint64_t value;
    uint32_t height;
    uint8_t  spk[KW_SPK_MAX];
    size_t   spklen;
} kw_utxo;

/* (total) is the sum of every value held, maintained on add and remove. It exists so
   the sum cannot wrap: an entry that would carry it past UINT64_MAX is refused, which
   makes every subset a caller sums afterwards safe by construction. Dogecoin has no
   supply cap and its issued supply is already 81% of what a uint64 holds, so this is
   nearer than it reads. */
typedef struct { kw_utxo *u; size_t count, cap; uint64_t total; } kw_utxoset;

int      kw_utxoset_init(kw_utxoset *us);
void     kw_utxoset_free(kw_utxoset *us);
size_t   kw_utxoset_count(const kw_utxoset *us);
uint64_t kw_utxoset_balance(const kw_utxoset *us);

/* Insert one UTXO. Returns 1, or 0 on a too-long script, out of memory, or a value
   that would carry the set's total past what a uint64 holds. */
int kw_utxoset_add(kw_utxoset *us, const uint8_t txid[32], uint32_t vout,
                   uint64_t value, uint32_t height, const uint8_t *spk, size_t spklen);

/* Persist the set as text, one "txid vout value height spk" line per UTXO (txid
   and spk hex, internal byte order). Load appends onto (us). Return 1, or 0 on
   an i/o or format error. */
int kw_utxoset_save(const kw_utxoset *us, const char *path);
int kw_utxoset_load(kw_utxoset *us, const char *path);

/* Apply one transaction at (height): remove UTXOs it spends, add outputs paying
   a watched script. Returns 1, or 0 if the transaction is malformed. */
int kw_utxoset_apply_tx(kw_utxoset *us, const kw_watchset *ws,
                        const uint8_t *rawtx, size_t len, uint32_t height);

#endif /* KOINU_UTXO_H */
