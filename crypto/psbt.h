/* koinu.dog - BIP174 partially signed transactions
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * The legacy subset, which is all Dogecoin has: a global unsigned transaction,
 * and per input a non-witness utxo, partial signatures, a sighash type, a
 * redeem script and a final scriptSig. Segwit fields (witness utxo, witness
 * script, PSBT_IN_FINAL_SCRIPTWITNESS) are not produced, and a transaction
 * carrying them is refused rather than silently mangled. Key-value pairs whose
 * type this does not know are refused for the same reason: a combiner that
 * drops what it does not understand is worse than one that stops.
 *
 * Serialization is the raw BIP174 byte stream. The base64 armour is a
 * presentation layer the caller can add; kw_hex handles the hex form the
 * wallet's other commands use. */

#ifndef KOINU_PSBT_H
#define KOINU_PSBT_H

#include <stddef.h>
#include <stdint.h>

#include "tx.h"
#include "ec.h"

#define KW_PSBT_MAX_SIGS   8      /* partial signatures per input */
#define KW_PSBT_SCRIPT_MAX 520    /* consensus limit on a redeem script */

typedef struct {
    uint8_t pubkey[33];
    uint8_t sig[KW_EC_SIG_DER_MAX + 1];   /* DER plus the hashtype byte */
    size_t  siglen;
} kw_psbt_sig;

typedef struct {
    uint8_t     *utxo;                    /* non-witness utxo, the whole prev tx */
    size_t       utxolen;
    kw_psbt_sig  sigs[KW_PSBT_MAX_SIGS];
    size_t       nsigs;
    uint32_t     sighash;
    int          has_sighash;
    uint8_t      redeem[KW_PSBT_SCRIPT_MAX];
    size_t       redeemlen;
    uint8_t      final[KW_TX_SCRIPT_MAX];  /* scriptSig, once assembled */
    size_t       finallen;
} kw_psbt_in;

typedef struct {
    uint8_t redeem[KW_PSBT_SCRIPT_MAX];
    size_t  redeemlen;
} kw_psbt_out;

typedef struct {
    kw_tx       tx;                       /* the unsigned transaction */
    kw_psbt_in  in[KW_TX_MAX_IN];
    kw_psbt_out out[KW_TX_MAX_OUT];
} kw_psbt;

/* Zero a psbt. Every psbt must be freed, since a parsed one owns its utxos. */
void kw_psbt_init(kw_psbt *p);
void kw_psbt_free(kw_psbt *p);

/* Creator: wrap (tx) as a psbt, blanking each input's scriptSig as BIP174
   requires of the unsigned transaction. Returns 1, or 0 if (tx) already
   carries a scriptSig. */
int kw_psbt_create(kw_psbt *p, const kw_tx *tx);

/* The unsigned transaction, for a caller that has to see what it is signing
   before it signs. Never NULL for a parsed or created psbt. */
const kw_tx *kw_psbt_unsigned_tx(const kw_psbt *p);

/* Updater: attach the redeem script an input spends, which is also the
   subscript kw_psbt_sign hashes. Returns 1. */
int kw_psbt_set_redeem(kw_psbt *p, size_t index, const uint8_t *script, size_t len);

/* Attach the previous transaction an input spends. Copies it. Returns 1. */
int kw_psbt_set_utxo(kw_psbt *p, size_t index, const uint8_t *rawtx, size_t len);

/* Signer: sign input (index) with (sk) over its redeem script and record the
   result as a partial signature, in place if this key already signed. Requires
   a redeem script and kw_ec_start(). Returns 1, 0 on failure, and -1 when the
   input already holds KW_PSBT_MAX_SIGS signatures from other keys. */
int kw_psbt_sign(kw_psbt *p, size_t index, const uint8_t sk[32], uint32_t hashtype);

/* Read back input (index)'s (n)th partial signature. Returns 1, or 0 if there
   is no such signature. */
int kw_psbt_get_sig(const kw_psbt *p, size_t index, size_t n,
                    uint8_t pubkey[33], uint8_t *sig, size_t *siglen);

/* Combiner: merge (src)'s signatures, scripts and utxos into (dst). Both must
   describe the same unsigned transaction. Returns 1, or 0 if they do not. */
int kw_psbt_combine(kw_psbt *dst, const kw_psbt *src);

/* Finalizer: set input (index)'s scriptSig, for scripts no standard finalizer
   can assemble (a payment channel's OP_IF branch, say). Returns 1. */
int kw_psbt_finalize(kw_psbt *p, size_t index, const uint8_t *scriptsig, size_t len);

/* Extractor: the network-serializable transaction, which needs a final
   scriptSig on every input. Returns 1, or 0 if one is missing. */
int kw_psbt_extract(const kw_psbt *p, kw_tx *tx);

/* The BIP174 byte stream. Returns the length written, or 0 if it does not
   fit. Parse returns 1, or 0 on a malformed, truncated, or segwit psbt. */
size_t kw_psbt_serialize(const kw_psbt *p, uint8_t *out, size_t outcap);
int    kw_psbt_parse(const uint8_t *in, size_t len, kw_psbt *p);

#endif /* KOINU_PSBT_H */
