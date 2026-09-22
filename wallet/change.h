/* koinu.dog - which change address a spend should use
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Shared because every front end that can sign has to rotate the same way. Two
 * front ends picking by different rules put change on the same address at
 * different times, which links the spends they were each avoiding linking.
 *
 * The utxo set alone is not enough to answer this. It holds unspent outputs, so
 * an index that was paid and then spent from disappears from it and looks fresh
 * again, and a wallet that keeps spending its whole balance walks a short cycle
 * of addresses. The journal is what remembers, since a spend records its change
 * when it is signed. */

#ifndef KOINU_CHANGE_H
#define KOINU_CHANGE_H

#include <stdint.h>

#include "bip32.h"
#include "chainparams.h"
#include "utxo.h"

/* The lowest change index under (n) that holds nothing and appears nowhere in
   the journal at (journal), which may be NULL or absent. Falls back to 0 when
   every one of them has been used, which is the address a wallet that never
   rotated would have used anyway, and sets (exhausted) so a caller can say so
   rather than reusing an address without telling anyone. (exhausted) may be
   NULL. */
uint32_t kw_change_index(const kw_bip32_key *master, const kw_chainparams *cp,
                         const kw_utxoset *us, const char *journal, int n,
                         int *exhausted);

#endif /* KOINU_CHANGE_H */
