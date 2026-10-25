/* koinu.dog - on-disk BIP158 filter cache
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * One basic filter per block, stored in height order (a 4-byte tag then each
 * block hash, filter length, and filter). Downloaded once; afterwards an
 * outpoint lookup or rescan tests watched scripts against the cached filters
 * locally and fetches only the blocks that match. */

#ifndef KOINU_CFSTORE_H
#define KOINU_CFSTORE_H

#include <stddef.h>
#include <stdint.h>

#include "peer.h"
#include "headers.h"
#include "gcs.h"

/* Append one block's filter. Creates the file (with its tag) if absent. 1/0. */
int  kw_cfstore_append(const char *path, const uint8_t block_hash[32],
                       const uint8_t *filter, size_t flen);

/* Number of filters cached (0 if the file is absent), or -1 if it is corrupt. */
long kw_cfstore_count(const char *path);

/* Ensure a filter is cached for every block in (s), fetching the missing suffix
   from (p) with getcfilters. Each fetched filter is verified against the peer's
   cfheaders commitment chain, whose verified tip persists in <path>.fh so a
   later delta must connect to it. Where the peer's network carries filter-header
   anchors, the chain is also checked against every anchor the range covers, so
   the base is not simply whatever the first peer claimed. Returns the cached
   count (== s->count) or -1, including on a commitment or anchor mismatch. */
long kw_cfstore_sync(kw_peer *p, const kw_headerstore *s, const char *path,
                     uint32_t base_height);

/* Stream the cache, testing (items) against each block's filter (keyed by the
   stored block hash), and append base_height+index for every match up to (cap).
   If (s) is non-NULL, verify each stored hash equals the header at that index.
   Returns the match count or -1. */
long kw_cfstore_match(const char *path, const kw_headerstore *s, uint32_t base_height,
                      const kw_gcs_item *items, size_t nitems,
                      uint32_t *heights, size_t cap);

/* Same, but only over blocks at height >= (from_height), seeking there through a
   <path>.idx height index (rebuilt when stale). For a from_height near the tip
   this touches only the tail of the cache. Returns the match count or -1. */
long kw_cfstore_match_range(const char *path, const kw_headerstore *s, uint32_t base_height,
                            uint32_t from_height, const kw_gcs_item *items, size_t nitems,
                            uint32_t *heights, size_t cap);

/* The filter-header chain over [from_height, from_height + cap), written to
   (out) as (cap) 32-byte headers, newest last. Returns how many were written,
   or -1.
 *
 * This is what makes a filter source checkable by someone who did not download
 * it: a filter header commits to its filter and to every filter beneath it, so
 * one header that chains to a compiled-in anchor settles the whole range below
 * it. Recomputed from the kept filters on each call rather than stored, because
 * the chain is a function of them and a second copy is a second thing to keep
 * honest.
 *
 * O(from_height - base_height) per call: it walks from the base to reach the
 * first requested height. A caller serving many ranges should ask for one wide
 * range, not many narrow ones. */
long kw_cfstore_headers(const char *path, uint32_t base_height, uint32_t from_height,
                        const uint8_t base[32], uint8_t *out, size_t cap);

/* The verified base that chain came from, read out of <path>.fh: the filter
   header of the block before the first cached filter. 1, or 0 if the sidecar is
   absent or never recorded one. A caller serving headers has to use this rather
   than assume a base, or it publishes a chain rooted somewhere the peer never
   agreed to. */
int kw_cfstore_base(const char *path, uint8_t out[32]);

#endif /* KOINU_CFSTORE_H */
