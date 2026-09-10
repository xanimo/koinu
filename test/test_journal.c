/* koinu.dog - wallet journal tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * A round trip through the file, the deduplication that lets a rescan run twice
 * without doubling a receive, the refusal to read a file it did not write, and the
 * mode it creates. The append is the part with money consequences: a lost entry is
 * a payment with no record of it. */

#include "journal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int fail;

static void bad(const char *what)
{
    fprintf(stderr, "FAIL: %s\n", what);
    fail = 1;
}

static void fill(kw_journal_entry *e, int dir, uint8_t byte, uint32_t vout,
                 uint32_t height, uint64_t amount, uint64_t fee, const char *addr)
{
    memset(e, 0, sizeof *e);
    e->when = 1757000000ULL + byte;
    e->dir = dir;
    memset(e->txid, byte, 32);
    e->vout = vout;
    e->height = height;
    e->amount = amount;
    e->fee = fee;
    snprintf(e->addr, sizeof e->addr, "%s", addr);
}

int main(void)
{
    char path[] = "/tmp/kw_journal_test_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) { bad("cannot make a temp file"); return 1; }
    close(fd);
    unlink(path);                       /* the journal creates it itself */

    /* an absent journal is not an error: nothing has happened yet */
    kw_journal j;
    if (!kw_journal_init(&j)) return 1;
    if (!kw_journal_load(&j, path)) bad("an absent journal must load as empty");
    if (j.count != 0) bad("an absent journal is not empty");
    kw_journal_free(&j);

    kw_journal_entry in, out;
    fill(&in, KW_JOURNAL_IN, 0x11, 0, 100, 500000000ULL, 0, "DMSxUULFs5YGKxwdJ7nAFEE72JewzPg8zn");
    fill(&out, KW_JOURNAL_OUT, 0x99, 0, 0, 250000000ULL, 22600ULL, "DTdestExampleAddress");
    if (!kw_journal_append(path, &in))  bad("append a receive");
    if (!kw_journal_append(path, &out)) bad("append a spend");

    /* the file it just wrote must read back byte for byte in the same order */
    kw_journal_init(&j);
    if (!kw_journal_load(&j, path)) bad("load what was just written");
    if (j.count != 2) bad("two entries did not come back");
    if (j.count == 2) {
        if (memcmp(&j.e[0], &in, sizeof in) != 0)   bad("the receive changed on the way through");
        if (memcmp(&j.e[1], &out, sizeof out) != 0) bad("the spend changed on the way through");
        if (j.e[0].dir != KW_JOURNAL_IN || j.e[1].dir != KW_JOURNAL_OUT) bad("direction swapped");
    }

    /* the same output, the other direction, is a different entry */
    if (!kw_journal_has(&j, in.txid, 0, KW_JOURNAL_IN))  bad("has() missed the receive");
    if (kw_journal_has(&j, in.txid, 0, KW_JOURNAL_OUT))  bad("has() confused the direction");
    if (kw_journal_has(&j, in.txid, 1, KW_JOURNAL_IN))   bad("has() confused the vout");
    kw_journal_free(&j);

    /* record() is append-unless-present, so a rescan does not double a receive */
    if (!kw_journal_record(path, &in)) bad("record an entry already there");
    if (!kw_journal_record(path, &out)) bad("record a spend already there");
    kw_journal_init(&j);
    kw_journal_load(&j, path);
    if (j.count != 2) bad("record() duplicated an entry that was already present");
    kw_journal_free(&j);

    /* a new output of the same transaction is a new entry */
    kw_journal_entry in2 = in;
    in2.vout = 1;
    in2.amount = 1;
    if (!kw_journal_record(path, &in2)) bad("record a second output of one transaction");
    kw_journal_init(&j);
    kw_journal_load(&j, path);
    if (j.count != 3) bad("vout 1 did not append alongside vout 0");
    kw_journal_free(&j);

    /* 0600: it names amounts and addresses */
    struct stat st;
    if (stat(path, &st) != 0) bad("stat");
    else if ((st.st_mode & 0777) != 0600) {
        fprintf(stderr, "FAIL: journal mode is %04o, want 0600\n", st.st_mode & 0777);
        fail = 1;
    }

    /* a file this did not write is refused rather than half read */
    FILE *f = fopen(path, "a");
    if (f) { fprintf(f, "this is not a journal line\n"); fclose(f); }
    kw_journal_init(&j);
    if (kw_journal_load(&j, path)) bad("a malformed line was accepted");
    kw_journal_free(&j);

    /* and nothing is appended to a file that cannot be parsed */
    if (kw_journal_record(path, &out)) bad("record() wrote to an unparseable journal");
    unlink(path);

    /* a short txid is not a txid */
    f = fopen(path, "w");
    if (f) { fprintf(f, "1757000000 in 1111 0 1 1 0 D\n"); fclose(f); }
    kw_journal_init(&j);
    if (kw_journal_load(&j, path)) bad("a 4-character txid was accepted");
    kw_journal_free(&j);
    unlink(path);

    /* an unknown direction is not a direction */
    f = fopen(path, "w");
    if (f) {
        fprintf(f, "1757000000 sideways 1111111111111111111111111111111111111111"
                   "111111111111111111111111 0 1 1 0 D\n");
        fclose(f);
    }
    kw_journal_init(&j);
    if (kw_journal_load(&j, path)) bad("an unknown direction was accepted");
    kw_journal_free(&j);
    unlink(path);

    if (fail) return 1;
    printf("journal ok: round trip, direction and vout in the dedup key, record() is\n"
           "  append-unless-present, 0600, and three malformed files refused\n");
    return 0;
}
