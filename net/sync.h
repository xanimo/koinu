/* koinu.dog - header chain sync driver
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#ifndef KOINU_SYNC_H
#define KOINU_SYNC_H

#include "peer.h"
#include "headers.h"
#include "chainparams.h"

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

#endif /* KOINU_SYNC_H */
