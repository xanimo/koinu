/* dogewallet - BIP44 account derivation
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#ifndef DOGEWALLET_BIP44_H
#define DOGEWALLET_BIP44_H

#include <stdint.h>

#include "bip32.h"

/* Derive m/44'/coin'/account'/change/index from a private master. change is 0
   for receiving and 1 for change addresses. Returns 1 on success, 0 if the
   master is not private or an index is unusable. */
int dw_bip44_derive(const dw_bip32_key *master,
                    uint32_t coin, uint32_t account, uint32_t change, uint32_t index,
                    dw_bip32_key *out);

#endif /* DOGEWALLET_BIP44_H */
