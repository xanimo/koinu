/* koinu.dog - transaction building, legacy sighash, P2PKH signing
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Legacy (pre-segwit) serialization only, which is what Dogecoin uses. Bounded
 * fixed arrays rather than allocation; a builder assembles inputs and outputs,
 * then each input is signed with SIGHASH_ALL. */

#ifndef KOINU_TX_H
#define KOINU_TX_H

#include <stddef.h>
#include <stdint.h>

#define KW_TX_MAX_IN     32
#define KW_TX_MAX_OUT    32
#define KW_TX_SCRIPT_MAX 256
#define KW_SIGHASH_ALL   1

typedef struct {
    uint8_t  prevout[32];                 /* internal byte order */
    uint32_t vout;
    uint8_t  script[KW_TX_SCRIPT_MAX];    /* scriptSig; empty until signed */
    size_t   scriptlen;
    uint32_t sequence;
} kw_txin;

typedef struct {
    uint64_t value;
    uint8_t  script[KW_TX_SCRIPT_MAX];    /* scriptPubKey */
    size_t   scriptlen;
} kw_txout;

typedef struct {
    uint32_t version;
    kw_txin  vin[KW_TX_MAX_IN];
    size_t   nin;
    kw_txout vout[KW_TX_MAX_OUT];
    size_t   nout;
    uint32_t locktime;
} kw_tx;

/* version 1, no inputs or outputs, locktime 0. */
void kw_tx_init(kw_tx *tx);

/* Add an input spending (txid_hex:vout), txid in display (reversed) form, with a
   final sequence and an empty scriptSig. Returns 1, or 0 if full or txid bad. */
int  kw_tx_add_input(kw_tx *tx, const char *txid_hex, uint32_t vout);

/* Add an output. add_output_p2pkh builds 76a914<hash160>88ac. Returns 1, or 0
   if full or the script is too long. */
int  kw_tx_add_output(kw_tx *tx, uint64_t value, const uint8_t *script, size_t scriptlen);
int  kw_tx_add_output_p2pkh(kw_tx *tx, uint64_t value, const uint8_t hash160[20]);

/* Serialize the transaction (with whatever scriptSigs are set). Returns length
   or 0 if it would not fit. */
size_t kw_tx_serialize(const kw_tx *tx, uint8_t *out, size_t outcap);

/* Legacy SIGHASH_ALL digest for (index), with (subscript) standing in for that
   input's scriptSig and all other scriptSigs blanked. Returns 1, or 0 on a bad
   index or unsupported hashtype. */
int  kw_tx_sighash(const kw_tx *tx, size_t index,
                   const uint8_t *subscript, size_t subscriptlen,
                   uint32_t hashtype, uint8_t out[32]);

/* Sign input (index) as P2PKH: sighash over (prev_spk), then set the scriptSig
   to <sig||hashtype> <pubkey>. Derives the pubkey from (sk). Requires
   kw_ec_start(). Returns 1 on success. */
int  kw_tx_sign_p2pkh(kw_tx *tx, size_t index, const uint8_t sk[32],
                      const uint8_t *prev_spk, size_t prev_spk_len);

/* As kw_tx_sign_p2pkh, but pushing the uncompressed (65-byte) pubkey, for
   external keys whose address hashes that form. */
int  kw_tx_sign_p2pkh_uncompressed(kw_tx *tx, size_t index, const uint8_t sk[32],
                                   const uint8_t *prev_spk, size_t prev_spk_len);

/* Produce one input's signature over (subscript): the DER signature with the
   hashtype byte appended, ready to push into a scriptSig. This is the piece each
   party contributes when co-signing; (subscript) is the redeem script for P2SH.
   (*outlen) is the buffer size in and the signature length out. Returns 1. */
int  kw_tx_signature(const kw_tx *tx, size_t index, const uint8_t sk[32],
                     const uint8_t *subscript, size_t subscriptlen, uint32_t hashtype,
                     uint8_t *out, size_t *outlen);

/* Build an m-of-n bare multisig script (OP_m <pubkey..> OP_n OP_CHECKMULTISIG),
   used as a P2SH redeem script. Returns its length, or 0. */
size_t kw_script_multisig(int m, const uint8_t (*pubkeys)[33], int n, uint8_t *out, size_t cap);

/* The P2SH scriptPubKey (a914 <hash160(redeem)> 87) for a redeem script. */
size_t kw_script_p2sh(const uint8_t *redeem, size_t redeemlen, uint8_t out[23]);

/* Set input (index)'s scriptSig to redeem a P2SH multisig: OP_0 then each
   signature (in the redeem script's pubkey order) then the redeem script.
   Returns 1, or 0 if it does not fit. */
int  kw_tx_set_multisig(kw_tx *tx, size_t index, const uint8_t *const *sigs,
                        const size_t *siglens, size_t nsigs,
                        const uint8_t *redeem, size_t redeemlen);

/* Read an m-of-n bare multisig script back into its parts. Compressed keys
   only, the shape kw_script_multisig builds; (pubkeys) holds up to 16.
   Returns 1, or 0 if the script is not that shape. */
int  kw_script_multisig_parse(const uint8_t *script, size_t scriptlen,
                              int *m, uint8_t (*pubkeys)[33], int *n);

/* Parse a legacy serialized transaction into (tx), bounded by the builder's
   limits (KW_TX_MAX_IN/OUT, KW_TX_SCRIPT_MAX). Returns the bytes consumed
   (the tx length), or 0 if malformed or over a limit. */
size_t kw_tx_parse(const uint8_t *raw, size_t len, kw_tx *tx);

/* Double-SHA256 of the serialization, internal byte order (reverse for display). */
int  kw_tx_txid(const kw_tx *tx, uint8_t out[32]);

/* Walk a legacy (non-segwit) serialized transaction, reporting each input's
   prevout and each output. on_output receives this tx's txid (internal order),
   so a scanner can form the created outpoint. Dogecoin chain transactions are
   legacy, so txid is SHA256d over the whole tx. Returns the number of bytes
   consumed (the tx length, so a caller can walk a block) or 0 if malformed. */
size_t kw_tx_scan(const uint8_t *raw, size_t len, uint8_t txid[32],
                  void (*on_input)(void *ctx, const uint8_t prev_txid[32], uint32_t vout),
                  void (*on_output)(void *ctx, const uint8_t txid[32], uint32_t index,
                                    uint64_t value, const uint8_t *spk, size_t spklen),
                  void *ctx);

#endif /* KOINU_TX_H */
