/* koinu.dog - BIP157 compact-filter sync
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * The privacy-preferred backend. It pulls one basic filter per block
 * (getcfilters/cfilter), tests the watched scripts against each, and downloads
 * only the blocks that match. Needs a peer that serves BIP157; the classic SPV
 * backend is the fallback where a peer does not. Filter commitments
 * (getcfheaders/getcfcheckpt) are not yet verified, so the served filters are
 * trusted, matching the header sync's trust-the-served-chain stance. */

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

#endif /* KOINU_CF_H */
