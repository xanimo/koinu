/* koinu.dog - which change address a spend should use
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "change.h"
#include "journal.h"

#include "address.h"
#include "bip44.h"
#include "mem.h"
#include "ripemd160.h"

#include <string.h>

uint32_t kw_change_index(const kw_bip32_key *master, const kw_chainparams *cp,
                         const kw_utxoset *us, const char *journal, int n)
{
    if (!master || !cp) return 0;

    /* Initialised before anything can skip it: the journal is optional, and a
       short-circuit that left this struct untouched would hand kw_journal_free
       whatever the stack held. */
    kw_journal j;
    kw_journal_init(&j);
    int have_j = journal && kw_journal_load(&j, journal);

    uint32_t pick = 0;
    for (int i = 0; i < n; i++) {
        kw_bip32_key ck;
        if (!kw_bip44_derive(master, cp->bip44_coin, 0, 1, (uint32_t)i, &ck)) continue;
        uint8_t pub[33], h[20];
        char addr[64];
        kw_bip32_pubkey(&ck, pub);
        kw_hash160(pub, 33, h);
        size_t al = kw_address_p2pkh(pub, cp->p2pkh, addr, sizeof addr);
        kw_secure_zero(&ck, sizeof ck);

        int used = 0;
        for (size_t u = 0; us && u < us->count && !used; u++)
            if (us->u[u].spklen == 25 && memcmp(us->u[u].spk + 3, h, 20) == 0) used = 1;
        for (size_t e = 0; have_j && al && e < j.count && !used; e++)
            if (strcmp(j.e[e].addr, addr) == 0) used = 1;

        if (!used) { pick = (uint32_t)i; break; }
    }

    kw_journal_free(&j);
    return pick;
}
