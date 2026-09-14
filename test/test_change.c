/* koinu.dog - the shared change-index rule
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * kw_change_index decides where a spend's change goes, so both front ends have to
 * agree and neither may crash on the arguments its signature says it takes. */

#include "change.h"
#include "ec.h"
#include "address.h"
#include "bip32.h"
#include "bip44.h"
#include "chainparams.h"
#include "journal.h"
#include "ripemd160.h"
#include "utxo.h"

#include <stdio.h>
#include <string.h>

/* Leaves a pattern on the stack that a caller's uninitialised locals land in.
   Without this a struct that is never initialised reads as zeroes by luck and a
   free of its pointer looks harmless. */
static void dirty_stack(void)
{
    volatile unsigned char pad[4096];
    for (size_t i = 0; i < sizeof pad; i++) pad[i] = (unsigned char)(0xa5 + i);
}

/* the p2pkh scriptPubKey of change index (i) */
static void change_spk(const kw_bip32_key *master, const kw_chainparams *cp,
                       uint32_t i, uint8_t spk[25], char addr[64])
{
    kw_bip32_key ck;
    uint8_t pub[33], h[20];
    if (!kw_bip44_derive(master, cp->bip44_coin, 0, 1, i, &ck)) { spk[0] = 0; return; }
    kw_bip32_pubkey(&ck, pub);
    kw_hash160(pub, 33, h);
    spk[0] = 0x76; spk[1] = 0xa9; spk[2] = 0x14;
    memcpy(spk + 3, h, 20);
    spk[23] = 0x88; spk[24] = 0xac;
    if (addr) kw_address_p2pkh(pub, cp->p2pkh, addr, 64);
}

static void add_utxo(kw_utxoset *us, const uint8_t spk[25], uint32_t vout)
{
    uint8_t txid[32];
    memset(txid, 0x11, 32);
    kw_utxoset_add(us, txid, vout, 100000000ULL, 1, spk, 25);
}

int main(void)
{
    if (!kw_ec_start()) { fprintf(stderr, "FAIL: ec init\n"); return 1; }
    const kw_chainparams *cp = &KW_DOGE_REGTEST;
    uint8_t seed[64];
    for (int i = 0; i < 64; i++) seed[i] = (uint8_t)(i * 7 + 1);
    kw_bip32_key master;
    if (!kw_bip32_from_seed(seed, 64, cp->bip32, &master))
        { fprintf(stderr, "FAIL: master key\n"); return 1; }

    /* A NULL journal is what the signature says is allowed, and the guard inside
       exists for it. It used to leave the journal struct uninitialised and free
       it anyway, which is a free of whatever the stack held. */
    dirty_stack();
    kw_utxoset empty; kw_utxoset_init(&empty);
    if (kw_change_index(&master, cp, &empty, NULL, 8) != 0)
        { fprintf(stderr, "FAIL: nothing used, want index 0\n"); return 1; }
    dirty_stack();
    if (kw_change_index(&master, cp, NULL, NULL, 8) != 0)
        { fprintf(stderr, "FAIL: no utxo set and no journal, want index 0\n"); return 1; }
    dirty_stack();
    if (kw_change_index(&master, cp, &empty, "/nonexistent/journal", 8) != 0)
        { fprintf(stderr, "FAIL: absent journal, want index 0\n"); return 1; }

    /* an index the utxo set holds coins at is used */
    uint8_t spk0[25], spk1[25];
    char addr0[64], addr1[64];
    change_spk(&master, cp, 0, spk0, addr0);
    change_spk(&master, cp, 1, spk1, addr1);
    add_utxo(&empty, spk0, 0);
    if (kw_change_index(&master, cp, &empty, NULL, 8) != 1)
        { fprintf(stderr, "FAIL: index 0 holds coins, want index 1\n"); return 1; }

    /* and one the journal names, whether or not it still holds anything */
    const char *jp = "test_change.journal.tmp";
    remove(jp);
    kw_journal_entry e;
    memset(&e, 0, sizeof e);
    e.when = 1700000000; e.dir = KW_JOURNAL_IN; e.vout = 1;
    memset(e.txid, 0x22, 32);
    e.amount = 5000; e.height = 3;
    snprintf(e.addr, sizeof e.addr, "%s", addr1);
    if (!kw_journal_append(jp, &e)) { fprintf(stderr, "FAIL: could not write a journal\n"); return 1; }

    if (kw_change_index(&master, cp, &empty, jp, 8) != 2)
        { fprintf(stderr, "FAIL: 0 held and 1 journaled, want index 2\n"); return 1; }
    /* the journal alone is enough: no utxo set at all */
    if (kw_change_index(&master, cp, NULL, jp, 8) != 0)
        { fprintf(stderr, "FAIL: only 1 is journaled, want index 0\n"); return 1; }

    /* every index within reach used falls back to 0 rather than off the end */
    if (kw_change_index(&master, cp, &empty, NULL, 1) != 0)
        { fprintf(stderr, "FAIL: only index 0 in reach and it is used, want 0\n"); return 1; }
    if (kw_change_index(&master, cp, &empty, NULL, 0) != 0)
        { fprintf(stderr, "FAIL: nothing in reach, want 0\n"); return 1; }

    kw_utxoset_free(&empty);
    remove(jp);
    kw_ec_stop();
    printf("change ok: null journal and null utxo set, held index skipped, "
           "journaled index skipped,\n  both together, and a fallback when every one in reach is used\n");
    return 0;
}
