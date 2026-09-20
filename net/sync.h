/* koinu.dog - header chain sync driver
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#ifndef KOINU_SYNC_H
#define KOINU_SYNC_H

#include "peer.h"
#include "headers.h"
#include "chainparams.h"
#include "powq.h"
#include "pow.h"

/* Messages a peer may send in place of the headers it was asked for before the
   round is abandoned. A socket timeout only catches a peer that says nothing. */
#define KW_SYNC_MAX_SKIP 256

/* When nonzero, the sync drivers print progress to stderr. Off by default. */
extern int kw_net_verbose;

/* Walk the peer's header chain into (s): send getheaders with a locator built
   from the store tip, or from (cp)'s genesis when the store is empty, append
   what comes back, and repeat until the peer has no more. When seeding from an
   empty store, the first header must link to genesis or the sync is refused.
   Answers pings; ignores other messages. Returns the number of headers
   appended, or -1 on a socket error, an AuxPoW header, or one that does not
   link. */
long kw_sync_headers(kw_peer *p, kw_headerstore *s, const kw_chainparams *cp);

/* The same, handing every header at (from_height) or above to (q) as it arrives, so
   its work is checked while the download continues. (q) NULL is the plain sync.
   Below (from_height) a header is trusted because a compiled-in block hash already
   pins it, which is a stronger claim than its work: a hash names one chain, where
   work only proves someone burned energy on some chain. Pass 1 to check the lot and
   trust nothing. The verdict comes from kw_powq_finish, not from here. */
long kw_sync_headers_checked(kw_peer *p, kw_headerstore *s, const kw_chainparams *cp,
                             kw_powq *q, uint32_t from_height);

/* The most locator hashes kw_sync_locator writes. Ten single steps back from the
   tip, then doubling, plus the newest anchor and genesis. */
#define KW_SYNC_LOCATOR_MAX 40

/* Build a getheaders locator from (s): the tip, the nine below it, then back in
   doubling steps, ending at the newest anchor at or below the tip and genesis.
   Returns how many were written.

   A one-hash locator only works when the peer is on the same chain as us. A peer
   on a fork does not recognise our tip and answers with nothing, so a chain with
   more work is invisible; it answers from the first hash it does recognise, which
   is what makes the fork point findable. */
size_t kw_sync_locator(const kw_headerstore *s, const kw_chainparams *cp,
                       uint8_t (*out)[32], size_t max);

/* The accumulated work of the headers at heights (from, to], added into (out),
   which is not zeroed first. Returns 1, or 0 if the range is not in the store.

   Summed rather than compared header by header: two chains can differ in both
   length and difficulty, and only the total says which one cost more to build. */
int kw_sync_chainwork(const kw_headerstore *s, uint32_t from, uint32_t to,
                      kw_u256 *out);

/* Is (bits) the nBits the chain's own retarget rule demands at (height)? The rule is
   in net/pow.c and needs two timestamps from arbitrary earlier heights, which is why
   this lives with the store: (s) must already hold every height below this one, and
   genesis comes from (cp) since a store starts at height 1.

   1 when it matches, and 1 as well on a chain whose rules are not implemented, which
   is every network but mainnet: pretending to check would be worse than not. */
int kw_sync_bits_ok(const kw_headerstore *s, const kw_chainparams *cp,
                    uint32_t height, uint32_t bits);

/* Every anchor at or below the store's tip must name the block the store holds.
   Returns 1, or 0 with *bad_height set to the first anchor that does not match.

   For a cache read off disk this is the whole of the check. The sync verifies an
   anchor as the header passes, which does nothing for heights already present when it
   starts, and a cache is the persisted result of an earlier serving: not trusting a
   chain a peer served is the point, and a chain a peer served last week is the same
   chain. */
int kw_sync_anchors_ok(const kw_headerstore *s, const kw_chainparams *cp,
                       uint32_t *bad_height);

#endif /* KOINU_SYNC_H */
