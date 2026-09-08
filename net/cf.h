/* koinu.dog - BIP157 compact-filter sync
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * The privacy-preferred backend. It pulls one basic filter per block
 * (getcfilters/cfilter), tests the watched scripts against each, and downloads
 * only the blocks that match. Needs a peer that serves BIP157; the classic SPV
 * backend is the fallback where a peer does not.
 *
 * Every fetched filter is checked against the peer's committed filter-header
 * chain (getcfheaders): the filter must hash to the committed filter hash, and
 * each chunk's previous_filter_header must link to the chain already verified.
 * The cached store persists its verified tip, so a later delta sync must
 * connect to it and the peer cannot quietly rewrite cached history. The chain's
 * base is taken from the peer on first contact (there is no cross-peer
 * checkpoint comparison; single-peer, trust-on-first-use). */

#ifndef KOINU_CF_H
#define KOINU_CF_H

#include <stddef.h>
#include <stdint.h>

#include "peer.h"
#include "headers.h"
#include "utxo.h"

#define KW_CF_TYPE_BASIC 0x00

/* Build a getcfilters: filter type, start height, stop block hash (internal
   order). Returns length or 0. */
size_t kw_msg_getcfilters_build(uint8_t type, uint32_t start_height,
                                const uint8_t stop_hash[32], uint8_t *out, size_t outcap);

/* Parse a cfilter: filter type, block hash, then the filter bytes. On success
   returns 1 and points (filter)/(flen) at storage inside (payload). */
int kw_msg_cfilter_parse(const uint8_t *payload, size_t len,
                         uint8_t *type, uint8_t block_hash[32],
                         const uint8_t **filter, size_t *flen);

/* Build a getcfheaders: filter type, start height, stop block hash (internal
   order), the same layout as getcfilters. Returns length or 0. */
size_t kw_msg_getcfheaders_build(uint8_t type, uint32_t start_height,
                                 const uint8_t stop_hash[32], uint8_t *out, size_t outcap);

/* Parse a cfheaders: filter type, stop hash, previous filter header, then the
   filter hashes. On success returns 1 and points (hashes) at (nhashes)
   contiguous 32-byte entries inside (payload). */
int kw_msg_cfheaders_parse(const uint8_t *payload, size_t len,
                           uint8_t *type, uint8_t stop_hash[32], uint8_t prev_header[32],
                           const uint8_t **hashes, size_t *nhashes);

/* One link of the BIP157 filter-header chain:
   out = sha256d(filter_hash || prev). out may alias prev. */
void kw_cf_header_step(const uint8_t filter_hash[32], const uint8_t prev[32], uint8_t out[32]);

/* Fetch the committed filter-header chain for store range [s0,s1): the peer's
   previous_filter_header lands in (prev), the per-block filter hashes in
   (hashes), s1-s0 entries. Returns 1, or 0 on a wire error or a response that
   does not cover the range. */
int kw_cf_fetch_headers(kw_peer *p, const kw_headerstore *s, uint32_t base_height,
                        size_t s0, size_t s1, uint8_t prev[32], uint8_t (*hashes)[32]);

/* Fetch a basic filter for every block in the store, and for each block whose
   filter matches a watched script download and scan it into (us). (base_height)
   is the block height of store index 0. Returns the number of blocks scanned,
   or -1 on error. */
long kw_cf_sync(kw_peer *p, const kw_headerstore *s,
                kw_utxoset *us, const kw_watchset *ws, uint32_t base_height);

/* Same, but backed by the on-disk filter cache at (filters_path): fetch only the
   filters not yet cached, match locally, then download and scan the matching
   blocks. Returns blocks scanned, or -1. */
long kw_cf_scan_cached(kw_peer *p, const kw_headerstore *s,
                       kw_utxoset *us, const kw_watchset *ws, uint32_t base_height,
                       const char *filters_path);

/* The status of an outpoint over [since, tip], from the filter cache. status:
   0 unspent (height,value set), 1 spent (height set), 2 not seen in range. */
typedef struct { int status; long height; uint64_t value; long tipheight; } kw_outpoint_result;

/* Fill (res) for (txid,vout) paying (spk), testing cached filters over
   [since, tip] and reading only the matching blocks. Updates the filter cache
   delta first. Returns 1, or -1 on error. Reused by the daemon so a resident
   header store and peer answer queries without reloading. */
int kw_query_outpoint_range(kw_peer *p, const kw_headerstore *s, const char *filters_path,
                            uint32_t base_height, const uint8_t *spk, size_t spklen,
                            const uint8_t txid[32], uint32_t vout, uint32_t since,
                            kw_outpoint_result *res);

#endif /* KOINU_CF_H */
