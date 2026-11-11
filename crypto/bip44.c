/* koinu.dog - BIP44 account derivation
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "bip44.h"

#include "address.h"
#include "mem.h"

#include <stdio.h>

int kw_bip44_derive(const kw_bip32_key *master,
                    uint32_t coin, uint32_t account, uint32_t change, uint32_t index,
                    kw_bip32_key *out)
{
    if (!master->is_private) return 0;
    if (coin >= KW_BIP32_HARDENED || account >= KW_BIP32_HARDENED ||
        change >= KW_BIP32_HARDENED || index >= KW_BIP32_HARDENED)
        return 0;

    /* Reuse the tested path parser rather than open-code five derivations. */
    char path[64];
    int n = snprintf(path, sizeof path, "m/44'/%u'/%u'/%u/%u",
                     coin, account, change, index);
    if (n < 0 || (size_t)n >= sizeof path) return 0;
    return kw_bip32_derive_path(master, path, out);
}

int kw_bip44_address(const kw_chainparams *cp, const uint8_t *seed, size_t seedlen,
                     uint32_t account, uint32_t change, uint32_t index,
                     char *out, size_t outcap)
{
    kw_bip32_key master, key;
    int ok;

    if (!cp || !seed || !out || !outcap) return 0;
    /* BIP32 puts a seed between 128 and 512 bits and kw_bip32_from_seed bounds
       nothing, so a caller that got seedlen wrong gets a working wallet from
       whatever entropy it actually passed, which is the kind of mistake that
       looks like success until the funds are gone. Bounded here because this
       function is new and has no caller to break; narrowing from_seed itself
       would be a soname bump for a rule only this side of the api states. */
    if (seedlen < 16 || seedlen > 64) return 0;

    /* Locked, not only wiped. The early return on a failed pubkey used to skip
       the cleanup below, which is the one path out that left both of these in
       memory unwiped. */
    kw_secure_keep(&master, sizeof master);
    kw_secure_keep(&key, sizeof key);
    ok = kw_bip32_from_seed(seed, seedlen, cp->bip32, &master) &&
         kw_bip44_derive(&master, cp->bip44_coin, account, change, index, &key);
    if (ok) {
        uint8_t pub[33];
        ok = kw_bip32_pubkey(&key, pub) &&
             kw_address_p2pkh(pub, cp->p2pkh, out, outcap) != 0;
    }
    kw_secure_forget(&master, sizeof master);
    kw_secure_forget(&key, sizeof key);
    if (!ok) out[0] = 0;
    return ok;
}
