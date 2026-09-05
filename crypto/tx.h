/* dogewallet - transaction building, legacy sighash, P2PKH signing
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Legacy (pre-segwit) serialization only, which is what Dogecoin uses. Bounded
 * fixed arrays rather than allocation; a builder assembles inputs and outputs,
 * then each input is signed with SIGHASH_ALL. */

#ifndef DOGEWALLET_TX_H
#define DOGEWALLET_TX_H

#include <stddef.h>
#include <stdint.h>

#define DW_TX_MAX_IN     32
#define DW_TX_MAX_OUT    32
#define DW_TX_SCRIPT_MAX 256
#define DW_SIGHASH_ALL   1

typedef struct {
    uint8_t  prevout[32];                 /* internal byte order */
    uint32_t vout;
    uint8_t  script[DW_TX_SCRIPT_MAX];    /* scriptSig; empty until signed */
    size_t   scriptlen;
    uint32_t sequence;
} dw_txin;

typedef struct {
    uint64_t value;
    uint8_t  script[DW_TX_SCRIPT_MAX];    /* scriptPubKey */
    size_t   scriptlen;
} dw_txout;

typedef struct {
    uint32_t version;
    dw_txin  vin[DW_TX_MAX_IN];
    size_t   nin;
    dw_txout vout[DW_TX_MAX_OUT];
    size_t   nout;
    uint32_t locktime;
} dw_tx;

/* version 1, no inputs or outputs, locktime 0. */
void dw_tx_init(dw_tx *tx);

/* Add an input spending (txid_hex:vout), txid in display (reversed) form, with a
   final sequence and an empty scriptSig. Returns 1, or 0 if full or txid bad. */
int  dw_tx_add_input(dw_tx *tx, const char *txid_hex, uint32_t vout);

/* Add an output. add_output_p2pkh builds 76a914<hash160>88ac. Returns 1, or 0
   if full or the script is too long. */
int  dw_tx_add_output(dw_tx *tx, uint64_t value, const uint8_t *script, size_t scriptlen);
int  dw_tx_add_output_p2pkh(dw_tx *tx, uint64_t value, const uint8_t hash160[20]);

/* Serialize the transaction (with whatever scriptSigs are set). Returns length
   or 0 if it would not fit. */
size_t dw_tx_serialize(const dw_tx *tx, uint8_t *out, size_t outcap);

/* Legacy SIGHASH_ALL digest for (index), with (subscript) standing in for that
   input's scriptSig and all other scriptSigs blanked. Returns 1, or 0 on a bad
   index or unsupported hashtype. */
int  dw_tx_sighash(const dw_tx *tx, size_t index,
                   const uint8_t *subscript, size_t subscriptlen,
                   uint32_t hashtype, uint8_t out[32]);

/* Sign input (index) as P2PKH: sighash over (prev_spk), then set the scriptSig
   to <sig||hashtype> <pubkey>. Derives the pubkey from (sk). Requires
   dw_ec_start(). Returns 1 on success. */
int  dw_tx_sign_p2pkh(dw_tx *tx, size_t index, const uint8_t sk[32],
                      const uint8_t *prev_spk, size_t prev_spk_len);

/* Double-SHA256 of the serialization, internal byte order (reverse for display). */
int  dw_tx_txid(const dw_tx *tx, uint8_t out[32]);

#endif /* DOGEWALLET_TX_H */
