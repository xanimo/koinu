/* koinu.dog - what happened to this wallet, in order
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * The UTXO set answers what the wallet holds now. It cannot answer what happened,
 * because an output that gets spent is removed and a payment out leaves nothing
 * behind at all. So a spend is recorded when it is signed, and a receive when a
 * scan first sees it, into an append-only sidecar next to the utxo set.
 *
 * Two things this is not. It is not derived from the chain, so it starts empty and
 * says nothing about a wallet's past: coins received before the first scan that
 * carries this code are already spent or already counted, and nothing kept the
 * data to backfill them. And a recorded spend is one that was signed here, not one
 * that confirmed; until it does, or until a scan sees its effect, the entry is a
 * statement of intent.
 *
 * One line an entry, "when dir txid vout height amount fee addr", whitespace
 * separated, txid hex in internal byte order as the utxo set writes it. The file
 * is created 0600: it names amounts and addresses. */

#ifndef KOINU_JOURNAL_H
#define KOINU_JOURNAL_H

#include <stddef.h>
#include <stdint.h>

#define KW_JOURNAL_IN  0
#define KW_JOURNAL_OUT 1

typedef struct {
    uint64_t when;          /* unix seconds when recorded, not block time */
    int      dir;
    uint8_t  txid[32];      /* internal byte order */
    uint32_t vout;          /* the output this entry is about */
    uint32_t height;        /* 0 when not known, which is every fresh spend */
    uint64_t amount;
    uint64_t fee;           /* a spend's fee; 0 on a receive */
    char     addr[80];      /* where it went, or which of ours was paid */
} kw_journal_entry;

typedef struct { kw_journal_entry *e; size_t count, cap; } kw_journal;

int  kw_journal_init(kw_journal *j);
void kw_journal_free(kw_journal *j);

/* <utxos>.journal. Returns (out). */
char *kw_journal_path(const char *utxos, char *out, size_t cap);

/* Load appends onto (j), oldest line first. Returns 1 when the file is absent
   (nothing has happened yet) or read cleanly, 0 only if a line is malformed. */
int  kw_journal_load(kw_journal *j, const char *path);

/* Append one entry, creating the file 0600. Returns 1/0. */
int  kw_journal_append(const char *path, const kw_journal_entry *e);

/* 1 if (j) already holds this output in this direction, so a rescan does not
   record the same receive twice. */
int  kw_journal_has(const kw_journal *j, const uint8_t txid[32], uint32_t vout, int dir);

/* Append unless the file already holds this output in this direction, so signing
   the same spend twice records it once. Returns 1 if the entry is present when
   this returns, appended or already there, 0 on an i/o or format error. Loading
   for one append is the wrong shape for many, which is why record_receives in
   cli/kw.c loads once and uses the two calls above. */
int  kw_journal_record(const char *path, const kw_journal_entry *e);

#endif /* KOINU_JOURNAL_H */
