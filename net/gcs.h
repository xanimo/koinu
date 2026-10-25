/* koinu.dog - BIP158 basic block filter (Golomb-coded set)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * A compact, probabilistic set of the scripts touched by a block: every output
 * script (bar empty and OP_RETURN) and every spent-output script. A light client
 * tests its watched scripts against the filter and downloads only the blocks
 * that match, so the peer serves the same filter to everyone and never learns
 * which scripts are ours. Only the client side (decode and match) is here. */

#ifndef KOINU_GCS_H
#define KOINU_GCS_H

#include <stddef.h>
#include <stdint.h>

#define KW_GCS_P 19          /* Golomb-Rice parameter for the basic filter */
#define KW_GCS_M 784931      /* range multiplier for the basic filter */

typedef struct { const uint8_t *script; size_t len; } kw_gcs_item;

/* Return 1 if any of (items) is in the filter (filt,flen) keyed by the block
   hash (internal order, first 16 bytes used), 0 if none, -1 if malformed. */
int kw_gcs_match_any(const uint8_t *filt, size_t flen, const uint8_t block_hash[32],
                     const kw_gcs_item *items, size_t nitems);

/* Decode the filter's N sorted values into (out). Returns N, or -1 if malformed
   or N exceeds (cap). For tests and inspection. */
long kw_gcs_decode(const uint8_t *filt, size_t flen, uint64_t *out, size_t cap);

/* 1 if every one of (items) is in the filter, 0 if one is not, with its index
   written to (missing), and -1 if the filter is malformed.
 *
 * This is the half of a filter a light client can check for itself. A filter
 * names the scripts a block touches, and the dangerous lie is omission: leave
 * out the script that was paid, and a wallet never fetches the block and never
 * sees the payment. For a block already in hand, every scriptPubKey it creates
 * has to appear here, so an omission is caught by looking rather than trusted.
 *
 * What it cannot check is the other half. A basic filter also carries the
 * scripts the block spends, which live in the outputs its inputs consume and
 * are not in the block. Those need the chain's unspent set, which is a node's
 * job and not this library's. So a pass means the filter covers what this block
 * creates, not that the filter is complete. Skip OP_RETURN outputs before
 * calling: BIP158 excludes them, so their absence is correct. */
int kw_gcs_covers(const uint8_t *filt, size_t flen, const uint8_t block_hash[32],
                  const kw_gcs_item *items, size_t nitems, size_t *missing);

/* The filter value an element maps to, given the element count N. */
uint64_t kw_gcs_hash(const uint8_t block_hash[32], uint64_t N,
                     const uint8_t *e, size_t elen);

#endif /* KOINU_GCS_H */
