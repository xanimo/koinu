/* koinu.dog - watched scripts and the tracked UTXO set
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "utxo.h"
#include "tx.h"
#include "hex.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ── watch set ───────────────────────────────────────────────── */
int kw_watchset_init(kw_watchset *ws)
{
    ws->count = 0;
    ws->cap = 8;
    ws->w = (kw_watch *)malloc(ws->cap * sizeof *ws->w);
    return ws->w != NULL;
}

int kw_watchset_add(kw_watchset *ws, const uint8_t *spk, size_t len)
{
    if (len == 0 || len > KW_SPK_MAX) return 0;
    if (kw_watchset_has(ws, spk, len)) return 1;
    if (ws->count == ws->cap) {
        size_t nc = ws->cap * 2;
        kw_watch *nw = (kw_watch *)realloc(ws->w, nc * sizeof *nw);
        if (!nw) return 0;
        ws->w = nw; ws->cap = nc;
    }
    memcpy(ws->w[ws->count].spk, spk, len);
    ws->w[ws->count].len = len;
    ws->count++;
    return 1;
}

int kw_watchset_has(const kw_watchset *ws, const uint8_t *spk, size_t len)
{
    for (size_t i = 0; i < ws->count; i++)
        if (ws->w[i].len == len && memcmp(ws->w[i].spk, spk, len) == 0) return 1;
    return 0;
}

void kw_watchset_free(kw_watchset *ws)
{
    free(ws->w);
    ws->w = NULL; ws->count = ws->cap = 0;
}

/* ── UTXO set ────────────────────────────────────────────────── */
int kw_utxoset_init(kw_utxoset *us)
{
    us->count = 0;
    us->total = 0;
    us->cap = 16;
    us->u = (kw_utxo *)malloc(us->cap * sizeof *us->u);
    return us->u != NULL;
}

void kw_utxoset_free(kw_utxoset *us)
{
    free(us->u);
    us->u = NULL; us->count = us->cap = 0;
}

size_t kw_utxoset_count(const kw_utxoset *us) { return us->count; }

uint64_t kw_utxoset_balance(const kw_utxoset *us) { return us->total; }

static void utxo_remove(kw_utxoset *us, const uint8_t txid[32], uint32_t vout)
{
    for (size_t i = 0; i < us->count; i++) {
        if (us->u[i].vout == vout && memcmp(us->u[i].txid, txid, 32) == 0) {
            us->total -= us->u[i].value;
            us->u[i] = us->u[us->count - 1];   /* swap-remove; order does not matter */
            us->count--;
            return;
        }
    }
}

int kw_utxoset_add(kw_utxoset *us, const uint8_t txid[32], uint32_t vout,
                   uint64_t value, uint32_t height, const uint8_t *spk, size_t spklen)
{
    if (spklen > KW_SPK_MAX) return 0;
    /* Refuse anything that would carry the total past what a uint64 holds. Dogecoin
       issues forever and its supply is already most of the range, so this is the
       check that keeps every balance and every input selection below from wrapping:
       a subset of a total that fits cannot itself overflow. */
    if (value > UINT64_MAX - us->total) return 0;
    if (us->count == us->cap) {
        size_t nc = us->cap * 2;
        kw_utxo *nu = (kw_utxo *)realloc(us->u, nc * sizeof *nu);
        if (!nu) return 0;
        us->u = nu; us->cap = nc;
    }
    kw_utxo *e = &us->u[us->count++];
    memcpy(e->txid, txid, 32);
    e->vout = vout;
    e->value = value;
    e->height = height;
    memcpy(e->spk, spk, spklen);
    e->spklen = spklen;
    us->total += value;
    return 1;
}

struct apply_ctx {
    kw_utxoset        *us;
    const kw_watchset *ws;
    uint32_t           height;
    int                ok;
};

static void on_input(void *vc, const uint8_t prev[32], uint32_t vout)
{
    struct apply_ctx *c = (struct apply_ctx *)vc;
    utxo_remove(c->us, prev, vout);
}

static void on_output(void *vc, const uint8_t txid[32], uint32_t index,
                      uint64_t value, const uint8_t *spk, size_t spklen)
{
    struct apply_ctx *c = (struct apply_ctx *)vc;
    if (spklen <= KW_SPK_MAX && kw_watchset_has(c->ws, spk, spklen))
        if (!kw_utxoset_add(c->us, txid, index, value, c->height, spk, spklen)) c->ok = 0;
}

int kw_utxoset_apply_tx(kw_utxoset *us, const kw_watchset *ws,
                        const uint8_t *rawtx, size_t len, uint32_t height)
{
    struct apply_ctx c = { us, ws, height, 1 };
    if (kw_tx_scan(rawtx, len, NULL, on_input, on_output, &c) == 0) return 0;
    return c.ok;
}


/* These files name amounts, heights and addresses, which is why the journal is
   0600, and it is the same wallet's business here. Written through a temp file
   in the same directory and renamed, so a reader never sees half a set: the old
   fopen("w") truncated in place, 0666 under umask, and a crash or a concurrent
   kwui refresh read whatever had reached the disk as a real balance. */
static FILE *open_private_temp(const char *path, char *tmp, size_t tmpcap)
{
    if ((size_t)snprintf(tmp, tmpcap, "%s.tmp", path) >= tmpcap) return NULL;
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return NULL;
    FILE *f = fdopen(fd, "w");
    if (!f) { close(fd); unlink(tmp); return NULL; }
    return f;
}

static int commit_temp(FILE *f, const char *tmp, const char *path, int ok)
{
    if (ok && fflush(f) != 0) ok = 0;
    if (ok && fsync(fileno(f)) != 0) ok = 0;
    if (fclose(f) != 0) ok = 0;
    if (ok && rename(tmp, path) != 0) ok = 0;
    if (!ok) { unlink(tmp); return 0; }

    /* the rename has to reach the disk too, or a crash leaves the old file */
    char dir[4200];
    snprintf(dir, sizeof dir, "%s", path);
    char *slash = strrchr(dir, '/');
    const char *d = ".";
    if (slash) { *slash = '\0'; d = dir[0] ? dir : "/"; }
    int dfd = open(d, O_RDONLY);
    if (dfd >= 0) { fsync(dfd); close(dfd); }
    return 1;
}

/* ── persistence ─────────────────────────────────────────────── */
int kw_utxoset_save(const kw_utxoset *us, const char *path)
{
    char tmp[4200];
    FILE *f = open_private_temp(path, tmp, sizeof tmp);
    if (!f) return 0;
    int ok = fprintf(f, "# koinu utxo set v1\n") > 0;
    for (size_t i = 0; i < us->count && ok; i++) {
        const kw_utxo *u = &us->u[i];
        char txid[65], spk[2 * KW_SPK_MAX + 1];
        if (!kw_hex_encode(u->txid, 32, txid, sizeof txid) ||
            !kw_hex_encode(u->spk, u->spklen, spk, sizeof spk)) { ok = 0; break; }
        if (fprintf(f, "%s %u %llu %u %s\n", txid, u->vout,
                    (unsigned long long)u->value, u->height, spk) < 0) ok = 0;
    }
    /* The count last, so a file that was cut short cannot load as a smaller
       balance. A line boundary or an even number of script bytes both parse. */
    if (ok && fprintf(f, "# end %llu\n", (unsigned long long)us->count) < 0) ok = 0;
    return commit_temp(f, tmp, path, ok);
}

int kw_scanmeta_write(const char *utxos_path, int64_t feerate, int extent)
{
    char p[4200], tmp[4300];
    if ((size_t)snprintf(p, sizeof p, "%s.meta", utxos_path) >= sizeof p) return 0;
    FILE *f = open_private_temp(p, tmp, sizeof tmp);
    if (!f) return 0;
    int ok = fprintf(f, "feerate %lld\ngap %d\n", (long long)feerate, extent) > 0;
    return commit_temp(f, tmp, p, ok);
}

void kw_scanmeta_read(const char *utxos_path, int64_t *feerate, int *extent)
{
    if (feerate) *feerate = 0;
    if (extent) *extent = 0;
    char p[4200];
    snprintf(p, sizeof p, "%s.meta", utxos_path);
    FILE *f = fopen(p, "r");
    if (!f) return;
    char key[32]; long long v;
    while (fscanf(f, "%31s %lld", key, &v) == 2) {
        if (!strcmp(key, "feerate") && feerate) *feerate = (int64_t)v;
        else if (!strcmp(key, "gap") && extent) *extent = (int)v;
    }
    fclose(f);
}

int kw_utxoset_load(kw_utxoset *us, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[4 + 2 * KW_SPK_MAX + 128];
    int ok = 1, ended = 0;
    unsigned long long endcount = 0, added = 0;
    while (ok && fgets(line, sizeof line, f)) {
        if (line[0] == '#') {
            if (sscanf(line, "# end %llu", &endcount) == 1) ended = 1;
            continue;
        }
        if (line[0] == '\n') continue;
        /* Every conversion is width-limited, including the last: a bare %s here let
           a long line in a tampered file write past spkhex and into the frame. The
           buffer is one over the longest legitimate script so an overlong token comes
           back at full width and is refused rather than silently truncated into a
           shorter script that parses. */
        char txidhex[128], spkhex[2 * KW_SPK_MAX + 2];
        /* sscanf takes a literal width, so tie it to the buffer here: a change to
           KW_SPK_MAX becomes a build error rather than a silent overflow. */
        _Static_assert(2 * KW_SPK_MAX + 2 == 130, "the %129s below tracks KW_SPK_MAX");
        unsigned vout, height; unsigned long long value;
        if (sscanf(line, "%127s %u %llu %u %129s", txidhex, &vout, &value, &height, spkhex) != 5) { ok = 0; break; }
        if (strlen(spkhex) > 2 * KW_SPK_MAX) { ok = 0; break; }
        uint8_t txid[32], spk[KW_SPK_MAX];
        size_t spklen = strlen(spkhex) / 2;
        if (strlen(txidhex) != 64 || spklen == 0 || spklen > KW_SPK_MAX ||
            !kw_hex_decode(txidhex, 64, txid, 32) ||
            !kw_hex_decode(spkhex, strlen(spkhex), spk, spklen)) { ok = 0; break; }
        if (!kw_utxoset_add(us, txid, vout, value, height, spk, spklen)) { ok = 0; break; }
        added++;
    }
    fclose(f);
    /* No end marker, or one that disagrees, means the file is not the whole set:
       it was cut short, or it predates the marker. Either way the balance it
       would load is not the balance, so say so instead of showing it. */
    if (ok && (!ended || endcount != added)) ok = 0;
    return ok;
}
