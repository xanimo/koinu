/* koinu.dog - BIP44 account derivation
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#ifndef KOINU_BIP44_H
#define KOINU_BIP44_H

#include <stdint.h>

#include <stddef.h>

#include "bip32.h"
#include "chainparams.h"

/* Derive m/44'/coin'/account'/change/index from a private master. change is 0
   for receiving and 1 for change addresses. Returns 1 on success, 0 if the
   master is not private or an index is unusable. */
int kw_bip44_derive(const kw_bip32_key *master,
                    uint32_t coin, uint32_t account, uint32_t change, uint32_t index,
                    kw_bip32_key *out);

/* The p2pkh address at m/44'/coin'/account'/change/index for (seed), written
   NUL-terminated to (out). Returns 1, or 0 on a seed this cannot derive from or
   a buffer too small.

   Here because every caller that wanted one composed it out of four calls and
   had to know that both the master and the child must be locked and wiped, not
   only wiped: a child key is the seed one step on, and a stack buffer holding
   one is pageable. koinu's own cli once returned early on a failed pubkey and
   left both in memory. An external consumer has no way to learn that from the
   headers, so the discipline belongs on this side of them.

   (seedlen) is 16 to 64 bytes, which is what BIP32 specifies.
   kw_bip32_from_seed bounds nothing and will derive a usable key from one byte,
   so a caller that gets the length wrong there gets a working wallet from
   whatever entropy it passed. That is checked here rather than there because
   this is new and has nothing to break. */
int kw_bip44_address(const kw_chainparams *cp, const uint8_t *seed, size_t seedlen,
                     uint32_t account, uint32_t change, uint32_t index,
                     char *out, size_t outcap);

#endif /* KOINU_BIP44_H */
