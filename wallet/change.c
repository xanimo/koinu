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

/* The rule itself, over whichever derivation the caller can do: the lowest
   index under (n) that holds nothing and appears nowhere in the journal. Both
   entry points come through here so there is one policy rather than two that
   agree today. */
static uint32_t change_pick(const kw_chainparams *cp, const kw_utxoset *us,
                            const char *journal, int n, int *exhausted,
                            int (*derive)(void *ctx, uint32_t index, uint8_t pub[33]),
                            void *ctx)
{
    kw_journal j;
    uint32_t pick = 0;
    int have_j, found = 0, i;

    if (exhausted) *exhausted = 0;
    if (!cp) return 0;

    /* Initialised before anything can skip it: the journal is optional, and a
       short-circuit that left this struct untouched would hand kw_journal_free
       whatever the stack held. */
    kw_journal_init(&j);
    have_j = journal && kw_journal_load(&j, journal);

    for (i = 0; i < n; i++) {
        uint8_t pub[33], h[20];
        char addr[64];
        size_t al, u, e;
        int used = 0;

        if (!derive(ctx, (uint32_t)i, pub)) continue;
        kw_hash160(pub, 33, h);
        al = kw_address_p2pkh(pub, cp->p2pkh, addr, sizeof addr);

        for (u = 0; us && u < kw_utxoset_count(us) && !used; u++) {
            const kw_utxo *e2 = kw_utxoset_at(us, u);
            if (e2->spklen == 25 && memcmp(e2->spk + 3, h, 20) == 0) used = 1;
        }
        for (e = 0; have_j && al && e < j.count && !used; e++)
            if (strcmp(j.e[e].addr, addr) == 0) used = 1;

        if (!used) { pick = (uint32_t)i; found = 1; break; }
    }

    if (exhausted) *exhausted = !found;
    kw_journal_free(&j);
    return pick;
}

struct priv_ctx { const kw_bip32_key *master; const kw_chainparams *cp; };

static int derive_priv(void *vc, uint32_t index, uint8_t pub[33])
{
    struct priv_ctx *c = (struct priv_ctx *)vc;
    kw_bip32_key ck;
    int ok;

    if (!kw_bip44_derive(c->master, c->cp->bip44_coin, 0, 1, index, &ck)) return 0;
    ok = kw_bip32_pubkey(&ck, pub);
    kw_secure_zero(&ck, sizeof ck);
    return ok;
}

uint32_t kw_change_index(const kw_bip32_key *master, const kw_chainparams *cp,
                         const kw_utxoset *us, const char *journal, int n,
                         int *exhausted)
{
    struct priv_ctx c;

    if (!master || !cp) { if (exhausted) *exhausted = 0; return 0; }
    c.master = master;
    c.cp = cp;
    return change_pick(cp, us, journal, n, exhausted, derive_priv, &c);
}

/* The change branch of the account key, derived once: m/.../1 is unhardened, so
   a public parent walks it. */
static int derive_pub(void *vc, uint32_t index, uint8_t pub[33])
{
    const kw_bip32_key *chain = (const kw_bip32_key *)vc;
    kw_bip32_key ck;

    if (!kw_bip32_ckd_pub(chain, index, &ck)) return 0;
    return kw_bip32_pubkey(&ck, pub);
}

uint32_t kw_change_index_pub(const kw_bip32_key *account, const kw_chainparams *cp,
                             const kw_utxoset *us, const char *journal, int n,
                             int *exhausted)
{
    kw_bip32_key chain;

    if (exhausted) *exhausted = 0;
    if (!account || !cp) return 0;
    if (!kw_bip32_ckd_pub(account, 1, &chain)) return 0;
    return change_pick(cp, us, journal, n, exhausted, derive_pub, &chain);
}
