/* koinu.dog - the wallet journal
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "journal.h"
#include "hex.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int kw_journal_init(kw_journal *j)
{
    if (!j) return 0;
    j->e = NULL; j->count = 0; j->cap = 0;
    return 1;
}

void kw_journal_free(kw_journal *j)
{
    if (!j) return;
    free(j->e);
    j->e = NULL; j->count = 0; j->cap = 0;
}

char *kw_journal_path(const char *utxos, char *out, size_t cap)
{
    snprintf(out, cap, "%s.journal", utxos ? utxos : "wallet.utxos");
    return out;
}

static int push(kw_journal *j, const kw_journal_entry *e)
{
    if (j->count == j->cap) {
        size_t want = j->cap ? j->cap * 2 : 32;
        kw_journal_entry *n = (kw_journal_entry *)realloc(j->e, want * sizeof *n);
        if (!n) return 0;
        j->e = n; j->cap = want;
    }
    j->e[j->count++] = *e;
    return 1;
}

int kw_journal_load(kw_journal *j, const char *path)
{
    if (!j || !path) return 0;
    FILE *f = fopen(path, "r");
    if (!f) return 1;                       /* nothing has happened yet */

    char line[512];
    int ok = 1;
    while (fgets(line, sizeof line, f)) {
        if (line[0] == '\n' || line[0] == '#') continue;
        kw_journal_entry e;
        memset(&e, 0, sizeof e);
        char dir[8], txid[80];
        unsigned long long when, amount, fee;
        unsigned vout, height;
        if (sscanf(line, "%llu %7s %79s %u %u %llu %llu %79s",
                   &when, dir, txid, &vout, &height, &amount, &fee, e.addr) != 8)
            { ok = 0; break; }
        if (strlen(txid) != 64 || !kw_hex_decode(txid, 64, e.txid, 32)) { ok = 0; break; }
        if      (!strcmp(dir, "in"))  e.dir = KW_JOURNAL_IN;
        else if (!strcmp(dir, "out")) e.dir = KW_JOURNAL_OUT;
        else { ok = 0; break; }
        e.when = when; e.vout = vout; e.height = height;
        e.amount = amount; e.fee = fee;
        if (!push(j, &e)) { ok = 0; break; }
    }
    fclose(f);
    return ok;
}

int kw_journal_append(const char *path, const kw_journal_entry *e)
{
    if (!path || !e) return 0;
    char txid[65];
    if (!kw_hex_encode(e->txid, 32, txid, sizeof txid)) return 0;

    char line[512];
    int n = snprintf(line, sizeof line, "%llu %s %s %u %u %llu %llu %s\n",
                     (unsigned long long)e->when,
                     e->dir == KW_JOURNAL_OUT ? "out" : "in",
                     txid, e->vout, e->height,
                     (unsigned long long)e->amount, (unsigned long long)e->fee,
                     e->addr[0] ? e->addr : "-");
    if (n <= 0 || (size_t)n >= sizeof line) return 0;

    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) return 0;
    size_t off = 0, len = (size_t)n;
    int ok = 1;
    while (off < len) {
        ssize_t w = write(fd, line + off, len - off);
        if (w <= 0) { ok = 0; break; }
        off += (size_t)w;
    }
    close(fd);
    return ok;
}

int kw_journal_has(const kw_journal *j, const uint8_t txid[32], uint32_t vout, int dir)
{
    if (!j) return 0;
    for (size_t i = 0; i < j->count; i++)
        if (j->e[i].dir == dir && j->e[i].vout == vout &&
            memcmp(j->e[i].txid, txid, 32) == 0) return 1;
    return 0;
}

int kw_journal_record(const char *path, const kw_journal_entry *e)
{
    if (!path || !e) return 0;
    kw_journal j;
    if (!kw_journal_init(&j)) return 0;
    if (!kw_journal_load(&j, path)) { kw_journal_free(&j); return 0; }
    int have = kw_journal_has(&j, e->txid, e->vout, e->dir);
    kw_journal_free(&j);
    return have ? 1 : kw_journal_append(path, e);
}
