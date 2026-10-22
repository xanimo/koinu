/* koinu.dog - the transaction layout, for this project's own code and tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Not a public header and not installed. kw_tx is opaque in tx.h because it is
 * 63264 bytes of fixed arrays that no caller should be holding on a frame, and
 * because a caller reading vin[i].script directly is a caller that has to know
 * an unsigned input carries a zero length rather than asking.
 *
 * The library builds transactions field by field, and test/test_tx.c checks the
 * serializer against byte vectors, both of which need the layout. */

#ifndef KOINU_TX_INTERNAL_H
#define KOINU_TX_INTERNAL_H

#include "tx.h"

typedef struct {
    uint8_t  prevout[32];                 /* internal byte order */
    uint32_t vout;
    uint8_t  script[KW_TX_SCRIPTSIG_MAX]; /* scriptSig; empty until signed */
    size_t   scriptlen;
    uint32_t sequence;
} kw_txin;

typedef struct {
    uint64_t value;
    uint8_t  script[KW_TX_SCRIPT_MAX];    /* scriptPubKey */
    size_t   scriptlen;
} kw_txout;

struct kw_tx {
    uint32_t version;
    kw_txin  vin[KW_TX_MAX_IN];
    size_t   nin;
    kw_txout vout[KW_TX_MAX_OUT];
    size_t   nout;
    uint32_t locktime;
};

#endif /* KOINU_TX_INTERNAL_H */
