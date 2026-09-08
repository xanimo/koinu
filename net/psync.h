/* koinu.dog - parallel checkpointed header download
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * The segments between chainparams checkpoints download concurrently, one
 * worker thread and one connection each, writing finished headers straight
 * into the KWH2 cache at their record offsets, so peak memory is a few
 * batches rather than the chain. Within a segment every header must link to
 * the one before it, and the segment's last header must hash to its end
 * checkpoint. No PoW runs in the checkpointed range: checkpoint-anchored
 * linkage validates it, the same stance as the AuxPoW skip. The tail past the
 * last checkpoint is the ordinary sequential sync. */

#ifndef KOINU_PSYNC_H
#define KOINU_PSYNC_H

#include "chainparams.h"
#include "peer.h"

/* Fetch one segment over (p): headers (start_height, end_height], starting
   from (start_hash), each record pwritten to (fd) at its height's offset.
   Returns 1, or 0 on a wire, linkage, or terminal-hash failure. */
int kw_psync_segment(kw_peer *p, int fd,
                     const uint8_t start_hash[32], uint32_t start_height,
                     const uint8_t end_hash[32], uint32_t end_height);

/* Fill (path) with the checkpointed range [1, last checkpoint] using (npeers)
   connections to (host:port), SOCKS5 via 127.0.0.1:9050 when (tor). Builds
   into <path>.part and renames only when every segment verified. Returns the
   last checkpoint height, 0 when (path) already exists or the chain has no
   checkpoints (nothing done, sync normally), or -1 on failure. */
long kw_psync_headers(const kw_chainparams *cp, const char *host, int port,
                      int tor, int npeers, const char *path);

#endif /* KOINU_PSYNC_H */
