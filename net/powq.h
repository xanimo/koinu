/* koinu.dog - a validator pool: proof of work checked off the download's back
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Downloading headers is network-bound and checking their work is CPU-bound, so the
 * two want to overlap rather than take turns. Submitting is what a download thread
 * does with a header it has just parsed; the pool hashes in the background and the
 * verdict is collected at the end.
 *
 * The queue is bounded, which is the point: if validation cannot keep pace the
 * submit blocks and the download slows to match, rather than the queue growing until
 * memory runs out. On this machine eight-at-a-time scrypt across four cores does
 * about 40k headers a second against a download of 33k, so the brake should rarely
 * engage, and if it does the cost is overlapped rather than added.
 *
 * A merged-mined header's work lives in its parent, and the AuxPoW blob carrying that
 * parent is discarded by the header store, which keeps 80 bytes and a hash. So the
 * blob has to be handed over here while the bytes are still in hand: this is a
 * producer and a consumer running alongside the download, not a pass over the store
 * afterwards.
 *
 * What is not checked here is whether a header's nBits is the one the retarget rule
 * demands. That needs timestamps from arbitrary earlier heights, which is the store's
 * business, not a worker's. */

#ifndef KOINU_POWQ_H
#define KOINU_POWQ_H

#include <stddef.h>
#include <stdint.h>

typedef struct kw_powq kw_powq;

/* Start (nthreads) workers with room for (depth) queued headers. (nthreads) at or
   below zero means one per core, which is the right number: the work is issue-bound
   and hyperthreads add nothing. Returns NULL on failure. */
kw_powq *kw_powq_start(int nthreads, size_t depth);

/* Hand over a header to check. (aux) is its AuxPoW blob, or NULL for a header that
   proves its own work; both are copied, so the caller's buffer is free immediately.
   Blocks while the queue is full. Returns 1, or 0 if the pool is already stopping or
   out of memory. */
int kw_powq_submit(kw_powq *q, uint32_t height, const uint8_t header[80],
                   const uint8_t *aux, size_t auxlen);

/* Drain, stop the workers, and free. Returns 1 if every header submitted proved its
   work. On a failure returns 0 and sets *bad_height to the lowest failing height
   among those the pool actually checked, and *checked to how many that was. Either
   pointer may be NULL.

   "Among those it checked" is the whole of the promise: the first failure stops the
   pool, so a header submitted after that is refused and never hashed. Submitted in
   height order, which is how a chain arrives, that makes the answer the lowest bad
   height in the chain. Submitted out of order it is whichever bad header got in
   first, and the width of a worker's batch decides that, so it differs between a
   machine with the wide scrypt core and one without. */
int kw_powq_finish(kw_powq *q, uint64_t *checked, uint32_t *bad_height);

/* How many workers the pool started, which is what a caller reports. */
int kw_powq_threads(const kw_powq *q);

#endif /* KOINU_POWQ_H */
