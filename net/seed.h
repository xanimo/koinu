/* koinu.dog - DNS seed resolution
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Resolves the chain's seeder hostnames into peer addresses so the parallel
 * header download has nodes to spread over without any --node given. Local
 * DNS only; a Tor session passes the hostnames to the proxy instead, which
 * resolves them without a local lookup to observe. */

#ifndef KOINU_SEED_H
#define KOINU_SEED_H

#include <stddef.h>

#include "chainparams.h"

#define KW_SEED_ADDRLEN 64

/* Resolve every seeder in (cp) and write up to (max) unique IPv4 addresses as
   dotted-quad strings into (out). Returns the number written, 0 when the chain
   has no seeders or nothing resolved. */
size_t kw_seed_resolve(const kw_chainparams *cp, char out[][KW_SEED_ADDRLEN], size_t max);

#endif /* KOINU_SEED_H */
