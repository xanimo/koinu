/* koinu.dog - choosing between the chains peers serve
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * kw_sync_headers takes the chain one peer serves. Every header in it has to prove
 * its work, so a chain of invented headers is refused, but a peer that withholds
 * the tip or serves a real fork with less work than the one it is hiding is
 * believed, because there is no second chain to compare against.
 *
 * This asks several peers and keeps the chain with the most work. Only above the
 * newest anchor: below one a compiled-in block hash names a single chain, which is
 * a stronger claim than work, so a fork below the newest anchor is refused rather
 * than weighed. That also bounds what this costs, since a candidate only ever
 * holds the headers above the fork point.
 *
 * The chain already in the store is a candidate too. A peer has to beat what is
 * cached, not merely differ from it. */

#ifndef KOINU_CHAINSEL_H
#define KOINU_CHAINSEL_H

#include "chainparams.h"
#include "headers.h"
#include "peer.h"

/* Why a run ended up where it did, for the caller to print. */
typedef struct {
    int      npeers;          /* peers asked */
    int      ncandidates;     /* those that served a chain that verified */
    int      winner;          /* index of the peer whose chain was kept, -1 for the cache */
    uint32_t fork_height;     /* where the kept chain left the one in the store */
    long     appended;        /* headers the kept chain holds above the fork, which on
                                 a reorganisation is not the net change: see fork_height */
    uint32_t bad_height;      /* set when a peer was dropped for a bad header */
    uint64_t pow_checked;     /* headers whose work was checked, over all candidates */
    int      threads;         /* validator threads one candidate's pool ran on */
} kw_chainsel_result;

/* Sync the tail from every peer in (peers) and leave (s) holding the chain with
   the most work among those that fork from what (s) already held. Each peer is
   asked against the same starting store, so a chain built on another peer's fork
   rather than on the cache is not resolvable and is dropped. That direction is
   safe: it can fail to adopt a heavier chain, never prefer a lighter one it
   actually weighed.

   (pow_from) is lowered to just above the newest anchor if it sits higher, so the
   range whose work is checked always covers the range whose work is counted. Headers at (pow_from) or above have their work checked, each
   candidate against its own validator pool, so one peer's bad header cannot
   condemn another's chain.

   Returns the number of headers appended to (s), 0 when the chain already in the
   store wins, or -1 when no peer served a chain that verified and the store was
   left as it was found. (out) may be NULL. */
long kw_sync_headers_best(kw_peer *const *peers, int npeers,
                          kw_headerstore *s, const kw_chainparams *cp,
                          uint32_t pow_from, kw_chainsel_result *out);

#endif /* KOINU_CHAINSEL_H */
