/* koinu.dog - parallel checkpointed header download
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * The segments between chainparams checkpoints download concurrently, one
 * worker thread and one connection each, each buffering its segment and
 * writing it into the KWH2 cache at its record offset only once verified, so
 * peak memory is one segment per worker. A worker with nothing pending races
 * the least-claimed in-flight segment, so one slow peer cannot hold the whole
 * run hostage; the first finisher wins under the lock and losers discard.
 * Within a segment every header must link to the one before it, and the
 * segment's last header must hash to its end checkpoint. No PoW runs in the
 * checkpointed range: checkpoint-anchored linkage validates it, the same
 * stance as the AuxPoW skip. The tail past the last checkpoint is the
 * ordinary sequential sync. */

#ifndef KOINU_PSYNC_H
#define KOINU_PSYNC_H

#include "chainparams.h"
#include "peer.h"

/* Fetch one segment over (p): headers (start_height, end_height], starting
   from (start_hash), written as KWH2 records into (out), which holds
   end_height - start_height of them. Nothing reaches the cache file until the
   whole segment verifies, so two workers racing the same segment can never
   interleave in it. Returns 1, or 0 on a wire, linkage, or terminal-hash
   failure. */
int kw_psync_segment(kw_peer *p, uint8_t *out,
                     const uint8_t start_hash[32], uint32_t start_height,
                     const uint8_t end_hash[32], uint32_t end_height);

/* Fill (path) with the checkpointed range [1, last checkpoint] using (npeers)
   connections spread round-robin over (hosts):(port), SOCKS5 via
   127.0.0.1:9050 when (tor); a worker rotates to the next host when its
   connection fails. Builds into <path>.part and renames only when every
   segment verified. Returns the last checkpoint height, 0 when (path) already
   exists or the chain has no checkpoints (nothing done, sync normally), or -1
   on failure. On a fill, (*best) points at the host with the best observed
   rate, so the caller's remaining single-peer work avoids a dead or slow
   node; pass NULL if unwanted. */
long kw_psync_headers(const kw_chainparams *cp, const char *const *hosts, size_t nhosts,
                      int port, int tor, int npeers, const char *path,
                      const char **best);

#endif /* KOINU_PSYNC_H */
