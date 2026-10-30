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
#define KW_TX_SCRIPT_MAX 256      /* a scriptPubKey */
/* The scriptCode a signature covers, which for a P2SH spend is the redeem
   script and so takes the 520-byte consensus limit on a pushed element rather
   than the bound on a scriptPubKey. A 1-of-8 multisig redeem script is 275
   bytes: a psbt would hold it and the sighash refused to cover it. */
#define KW_TX_SUBSCRIPT_MAX 520
/* A scriptSig, which is far larger: redeeming an m-of-n P2SH costs about 74
   bytes a signature plus the redeem script, and 1650 is what a node relays. */
#define KW_TX_SCRIPTSIG_MAX 1650
#define KW_SIGHASH_ALL   1

/* Opaque. 63264 bytes of fixed arrays, which is not a thing to leave on a
   caller's frame beside anything else: cmd_sign used to hold one of these and a
   32-entry array of extended keys at once. Read through the accessors below.

   The layout is in crypto/tx_internal.h, which this project's own code and
   tests include and which is not installed. */
typedef struct kw_tx kw_tx;

/* An empty transaction, version 1 and no inputs, or NULL. free takes NULL. */
kw_tx *kw_tx_new(void);
void   kw_tx_free(kw_tx *tx);

/* ── reading one ──────────────────────────────────────────────── */
uint32_t kw_tx_version(const kw_tx *tx);
uint32_t kw_tx_locktime(const kw_tx *tx);
size_t   kw_tx_nin(const kw_tx *tx);
size_t   kw_tx_nout(const kw_tx *tx);

/* Output (i): what it pays and to what script. The script is borrowed and
   valid until the transaction changes or is freed. Returns 0 if there is no
   such output. */
int kw_tx_output(const kw_tx *tx, size_t i, uint64_t *value,
                 const uint8_t **spk, size_t *spklen);

/* Input (i): the outpoint it spends, (txid) in internal byte order. */
int kw_tx_input_prevout(const kw_tx *tx, size_t i, uint8_t txid[32], uint32_t *vout);

/* Input (i)'s scriptSig, which is empty until it is signed. Returns 0 when
   there is no such input or it carries none, rather than a zero length. */
int kw_tx_input_script(const kw_tx *tx, size_t i, const uint8_t **ss, size_t *len);


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

/* 1 if (script) pushes (pub) as a 33-byte compressed key: 0x21 then the key,
   which is the only form a compressed pubkey takes in a script, whether the
   script is bare multisig or has branches around it. A signer uses this to
   refuse a script that does not name its own key, which is what separates
   "co-sign our 2-of-2" from "sign this p2pkh coin of yours". */
int  kw_script_names_key(const uint8_t *script, size_t scriptlen, const uint8_t pub[33]);

/* Whether (script) names (pub) and still needs somebody else: 1 if it does, 0
 * if a signature from (pub) alone could satisfy it.
 *
 * The question a co-signer has to ask before signing, and it is not the same as
 * the one kw_psbt_sign asks. That one refuses a script not naming the key, which
 * every signer wants. This refuses a script that names the key and nothing more,
 * which only a caller promising a second party is required wants: a general
 * signer holding a p2sh over one key has every right to spend it.
 *
 * Counted rather than matched against known shapes. Distinct keys first, since a
 * script spending with one key is a spend however it is dressed up, and a bare
 * p2pk, a 1-of-1, either with a trailing no-op, and an OP_IF with the same key in
 * both branches all reached a node's mempool as one-key spends. Then, where the
 * script is a standard multisig and says its own threshold, that threshold:
 * counting cannot tell a 2-of-2 from a 1-of-2 because both name two.
 *
 * A branching script is judged on the count alone, so a payment channel's
 * OP_IF ... CHECKSIG OP_ELSE 2 ... CHECKMULTISIG OP_ENDIF passes, which is
 * intended. A branch that this key can take alone inside such a script is the
 * counterparty's to read, and binding the script to the coin is what stops it
 * being a script of the signer's own choosing. */
int  kw_script_cosignable(const uint8_t *script, size_t scriptlen,
                          const uint8_t pub[33]);

/* How many distinct public keys the script pushes, counting both compressed and
   uncompressed, up to (cap). A script that pushes one key is one that key alone
   can satisfy however it is dressed up: 1-of-1 multisig, <pub> CHECKSIG with an
   OP_NOP after it, and an OP_IF with the same key in both branches all push one.
   A co-signing script names at least two. */
size_t kw_script_key_count(const uint8_t *script, size_t scriptlen, size_t cap);

/* Read an m-of-n bare multisig script back into its parts. Compressed keys
   only, the shape kw_script_multisig builds; (pubkeys) holds up to 16.
   Returns 1, or 0 if the script is not that shape. */
int  kw_script_multisig_parse(const uint8_t *script, size_t scriptlen,
                              int *m, uint8_t (*pubkeys)[33], int *n);

/* Parse a legacy serialized transaction into (tx), bounded by the builder's
   limits (KW_TX_MAX_IN/OUT, KW_TX_SCRIPT_MAX). Returns the bytes consumed
   (the tx length), or 0 if malformed or over a limit.

   Those limits size this wallet's fixed arrays, they are not consensus, so a
   valid chain transaction over any of them parses here as malformed. Use
   kw_tx_scan to walk a block transaction; it has no such bound. */
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
