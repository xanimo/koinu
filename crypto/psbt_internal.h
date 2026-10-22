/* koinu.dog - the psbt layout, for this project's own tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Not a public header and not installed. kw_psbt is opaque in psbt.h because
 * its layout has changed twice and a consumer should not be holding 182kB of
 * it on a frame; this file exists so test/test_psbt.c can still build the
 * states a hostile counterparty sends, which no public function will create:
 * a partial signature under someone else's pubkey, a signature that does not
 * verify, a sighash type the signer did not ask for.
 *
 * Reaching into the struct is the weaker way to test that. Those states arrive
 * as bytes, so the faithful test splices the key-value pair into a serialized
 * psbt and parses it, which is the path an attacker actually has. That rewrite
 * is not done, and until it is, this header is the honest way to keep the
 * coverage rather than lose it to the type change.
 *
 * test/test_install.sh would catch a public header including this one. */

#ifndef KOINU_PSBT_INTERNAL_H
#define KOINU_PSBT_INTERNAL_H

#include "psbt.h"
#include "tx_internal.h"   /* kw_psbt embeds a kw_tx */

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
    uint8_t      final[KW_TX_SCRIPTSIG_MAX];  /* scriptSig, once assembled */
    size_t       finallen;
} kw_psbt_in;

typedef struct {
    uint8_t redeem[KW_PSBT_SCRIPT_MAX];
    size_t  redeemlen;
} kw_psbt_out;

struct kw_psbt {
    kw_tx       tx;                       /* the unsigned transaction */
    kw_psbt_in  in[KW_TX_MAX_IN];
    kw_psbt_out out[KW_TX_MAX_OUT];
};

#endif /* KOINU_PSBT_INTERNAL_H */
