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
   from (p) with getcfilters. Returns the cached count (== s->count) or -1. */
long kw_cfstore_sync(kw_peer *p, const kw_headerstore *s, const char *path,
                     uint32_t base_height);

/* Stream the cache, testing (items) against each block's filter (keyed by the
   stored block hash), and append base_height+index for every match up to (cap).
   If (s) is non-NULL, verify each stored hash equals the header at that index.
   Returns the match count or -1. */
long kw_cfstore_match(const char *path, const kw_headerstore *s, uint32_t base_height,
                      const kw_gcs_item *items, size_t nitems,
                      uint32_t *heights, size_t cap);

#endif /* KOINU_CFSTORE_H */
