/* koinu.dog - header chain sync driver
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#ifndef KOINU_SYNC_H
#define KOINU_SYNC_H

#include "peer.h"
#include "headers.h"
#include "chainparams.h"
#include "powq.h"

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

/* Is (bits) the nBits the chain's own retarget rule demands at (height)? The rule is
   in net/pow.c and needs two timestamps from arbitrary earlier heights, which is why
   this lives with the store: (s) must already hold every height below this one, and
   genesis comes from (cp) since a store starts at height 1.

   1 when it matches, and 1 as well on a chain whose rules are not implemented, which
   is every network but mainnet: pretending to check would be worse than not. */
int kw_sync_bits_ok(const kw_headerstore *s, const kw_chainparams *cp,
                    uint32_t height, uint32_t bits);

#endif /* KOINU_SYNC_H */
