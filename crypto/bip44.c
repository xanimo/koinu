/* dogewallet - BIP44 account derivation
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "bip44.h"

#include <stdio.h>

int dw_bip44_derive(const dw_bip32_key *master,
                    uint32_t coin, uint32_t account, uint32_t change, uint32_t index,
                    dw_bip32_key *out)
{
    if (!master->is_private) return 0;
    if (coin >= DW_BIP32_HARDENED || account >= DW_BIP32_HARDENED ||
        change >= DW_BIP32_HARDENED || index >= DW_BIP32_HARDENED)
        return 0;

    /* Reuse the tested path parser rather than open-code five derivations. */
    char path[64];
    int n = snprintf(path, sizeof path, "m/44'/%u'/%u'/%u/%u",
                     coin, account, change, index);
    if (n < 0 || (size_t)n >= sizeof path) return 0;
    return dw_bip32_derive_path(master, path, out);
}
