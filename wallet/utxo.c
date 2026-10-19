/* koinu.dog - watched scripts and the tracked UTXO set
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "utxo.h"
#include "tx.h"
#include "hex.h"
#include "sha2.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
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
    ws->w[ws->count].seen = 0;      /* malloc'd, and the scan reads it to find the highest used index */
    ws->count++;
    return 1;
}

long kw_watchset_find(const kw_watchset *ws, const uint8_t *spk, size_t len)
{
    if (!ws || !spk) return -1;
    for (size_t i = 0; i < ws->count; i++)
        if (ws->w[i].len == len && memcmp(ws->w[i].spk, spk, len) == 0) return (long)i;
    return -1;
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
void kw_utxoset_observe(kw_utxoset *us, const kw_utxo_watcher *w)
{
    if (us) us->watch = w;
}

int kw_utxoset_init(kw_utxoset *us)
{
    us->count = 0;
    us->total = 0;
    us->watch = NULL;
    us->cap = 16;
    us->u = (kw_utxo *)malloc(us->cap * sizeof *us->u);
    return us->u != NULL;
}

void kw_utxoset_free(kw_utxoset *us)
{
    for (size_t i = 0; i < us->count; i++) free(us->u[i].prevtx);
    free(us->u);
    us->u = NULL; us->count = us->cap = 0;
}

size_t kw_utxoset_count(const kw_utxoset *us) { return us->count; }

uint64_t kw_utxoset_balance(const kw_utxoset *us) { return us->total; }

static void utxo_remove(kw_utxoset *us, const uint8_t txid[32], uint32_t vout,
                        uint32_t height, const uint8_t by[32])
{
    for (size_t i = 0; i < us->count; i++) {
        if (us->u[i].vout == vout && memcmp(us->u[i].txid, txid, 32) == 0) {
            /* reported before the entry goes, since afterwards there is nothing
               left to report: the value and the script are only here */
            if (us->watch && us->watch->spent)
                us->watch->spent(us->watch->ctx, us->u[i].txid, us->u[i].vout,
                                 us->u[i].value, us->u[i].spk, us->u[i].spklen,
                                 height, by);
            us->total -= us->u[i].value;
            free(us->u[i].prevtx);
            us->u[i] = us->u[us->count - 1];   /* swap-remove; order does not matter */
            us->count--;
            return;
        }
    }
}

int kw_utxo_mature(const kw_chainparams *cp, const kw_utxo *u, uint32_t tip_height)
{
    if (!u || !u->coinbase) return 1;
    if (tip_height < u->height) return 0;                /* not even confirmed yet */
    return tip_height - u->height + 1 >= kw_coinbase_maturity(cp, u->height);
}

uint64_t kw_utxoset_spendable(const kw_chainparams *cp, const kw_utxoset *us,
                              uint32_t tip_height)
{
    if (!us) return 0;
    uint64_t total = 0;
    for (size_t i = 0; i < us->count; i++)
        if (kw_utxo_mature(cp, &us->u[i], tip_height)) total += us->u[i].value;
    return total;
}

/* kw_tx_scan reports every output; this picks out the one the outpoint names and
   compares it with what was claimed. */
struct bind_ctx {
    uint32_t       vout;
    uint64_t       value;
    const uint8_t *spk;
    size_t         spklen;
    int            found, match;
};

static void bind_output(void *vc, const uint8_t txid[32], uint32_t index,
                        uint64_t value, const uint8_t *spk, size_t spklen)
{
    struct bind_ctx *b = (struct bind_ctx *)vc;

    (void)txid;
    if (index != b->vout) return;
    b->found = 1;
    b->match = (value == b->value && spklen == b->spklen &&
                memcmp(spk, b->spk, spklen) == 0);
}

int kw_utxo_bind(const uint8_t txid[32], uint32_t vout, uint64_t value,
                 const uint8_t *spk, size_t spklen,
                 const uint8_t *rawtx, size_t rawlen)
{
    struct bind_ctx b;
    uint8_t got[32];
    size_t used;

    if (!txid || !spk || !rawtx || spklen == 0) return 0;
    if (rawlen == 0 || rawlen > KW_UTXO_PREVTX_MAX) return 0;

    /* The whole of the claim rests on this hash: anything else the file says
       about the transaction is checked against bytes that produce this txid. */
    kw_hash256(rawtx, rawlen, got);
    if (memcmp(got, txid, 32) != 0) return 0;

    b.vout = vout; b.value = value; b.spk = spk; b.spklen = spklen;
    b.found = b.match = 0;
    /* kw_tx_scan rather than kw_tx_parse: a transaction on chain may hold more
       inputs or outputs than the wallet's own builder will ever make, and
       refusing to bind one of those would make its coins unspendable here. */
    used = kw_tx_scan(rawtx, rawlen, got, NULL, bind_output, &b);
    if (used != rawlen) return 0;          /* trailing bytes are not this tx */
    return b.found && b.match;
}

int kw_utxoset_add(kw_utxoset *us, const uint8_t txid[32], uint32_t vout,
                   uint64_t value, uint32_t height, const uint8_t *spk, size_t spklen,
                   int coinbase, const uint8_t *rawtx, size_t rawlen)
{
    uint8_t *keep = NULL;

    if (spklen > KW_SPK_MAX) return 0;
    if (rawtx) {
        if (!kw_utxo_bind(txid, vout, value, spk, spklen, rawtx, rawlen)) return 0;
        keep = (uint8_t *)malloc(rawlen);
        if (!keep) return 0;
        memcpy(keep, rawtx, rawlen);
    }
    /* Refuse anything that would carry the total past what a uint64 holds. Dogecoin
       issues forever and its supply is already most of the range, so this is the
       check that keeps every balance and every input selection below from wrapping:
       a subset of a total that fits cannot itself overflow. */
    if (value > UINT64_MAX - us->total) { free(keep); return 0; }
    if (us->count == us->cap) {
        size_t nc = us->cap * 2;
        kw_utxo *nu = (kw_utxo *)realloc(us->u, nc * sizeof *nu);
        if (!nu) { free(keep); return 0; }
        us->u = nu; us->cap = nc;
    }
    kw_utxo *e = &us->u[us->count++];
    memcpy(e->txid, txid, 32);
    e->vout = vout;
    e->value = value;
    e->height = height;
    memcpy(e->spk, spk, spklen);
    e->spklen = spklen;
    e->coinbase = coinbase ? 1 : 0;
    e->prevtx = keep;
    e->prevtxlen = keep ? rawlen : 0;
    us->total += value;
    return 1;
}

struct apply_ctx {
    kw_utxoset  *us;
    kw_watchset *ws;
    int          coinbase;        /* the transaction being walked spends nothing */
    int          ninput;
    uint32_t     height;
    int          ok;
    uint8_t      txid[32];        /* the transaction being walked, for the record */
    const uint8_t *raw;           /* and its bytes, which every output it creates */
    size_t         rawlen;        /* carries so the amount can be checked later */
};

static void on_input(void *vc, const uint8_t prev[32], uint32_t vout)
{
    struct apply_ctx *c = (struct apply_ctx *)vc;
    /* inputs come before outputs, so by the time an output is reported this says
       whether the transaction creating it is a coinbase: one input, spending
       nothing */
    if (c->ninput++ == 0) {
        static const uint8_t zero[32] = { 0 };
        c->coinbase = (vout == 0xffffffffu && memcmp(prev, zero, 32) == 0);
    } else {
        c->coinbase = 0;
    }
    utxo_remove(c->us, prev, vout, c->height, c->txid);
}

static void on_output(void *vc, const uint8_t txid[32], uint32_t index,
                      uint64_t value, const uint8_t *spk, size_t spklen)
{
    struct apply_ctx *c = (struct apply_ctx *)vc;
    if (spklen > KW_SPK_MAX) return;
    long at = kw_watchset_find(c->ws, spk, spklen);
    if (at < 0) return;
    /* marked before the add, and never cleared by a later spend: this is what
       "used" means to the gap rule */
    c->ws->w[at].seen = 1;
    if (!kw_utxoset_add(c->us, txid, index, value, c->height, spk, spklen, c->coinbase,
                        c->raw, c->rawlen)) {
        c->ok = 0;
        return;
    }
    if (c->us->watch && c->us->watch->received)
        c->us->watch->received(c->us->watch->ctx, txid, index, value, spk, spklen,
                               c->height, c->coinbase);
}

int kw_utxoset_apply_tx(kw_utxoset *us, kw_watchset *ws,
                        const uint8_t *rawtx, size_t len, uint32_t height)
{
    struct apply_ctx c = { us, ws, 0, 0, height, 1, { 0 }, rawtx, len };
    /* kw_tx_scan fills the txid before the callbacks fire, so an input can name
       the transaction spending it */
    if (kw_tx_scan(rawtx, len, c.txid, on_input, on_output, &c) == 0) return 0;
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
    /* O_EXCL, so a symlink planted at <path>.tmp is not followed: without it the
       scan wrote through it, overwriting whatever it pointed at with the wallet's
       outputs and leaving that file's old mode. It also stops two scans on one
       path from sharing the temp file, where each would write half a set.
       O_NOFOLLOW is belt and braces on the same open. */
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0 && errno == EEXIST) {
        /* a temp file left by a killed run is ours to replace, once we know it is
           a plain file and not a link */
        struct stat st;
        if (lstat(tmp, &st) == 0 && S_ISREG(st.st_mode) && unlink(tmp) == 0)
            fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    }
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
    FILE *f;
    size_t i, j;
    int ok;

    /* An entry with no transaction behind it cannot have its amount checked by
       whoever loads this, and a file whose amounts cannot be checked is a file
       that decides what a signer pays the miner. */
    for (i = 0; i < us->count; i++)
        if (!us->u[i].prevtx) return 0;

    f = open_private_temp(path, tmp, sizeof tmp);
    if (!f) return 0;
    ok = fprintf(f, "# koinu utxo set v2\n") > 0;

    /* The creating transactions first, one per distinct txid: several outputs of
       one transaction are ordinary, and writing it per entry would multiply the
       file by the number of them the wallet holds. */
    for (i = 0; i < us->count && ok; i++) {
        const kw_utxo *u = &us->u[i];
        char txid[65];
        int seen = 0;

        for (j = 0; j < i; j++)
            if (memcmp(us->u[j].txid, u->txid, 32) == 0) { seen = 1; break; }
        if (seen) continue;

        if (!kw_hex_encode(u->txid, 32, txid, sizeof txid)) { ok = 0; break; }
        if (fprintf(f, "t %s ", txid) < 0) { ok = 0; break; }
        for (j = 0; j < u->prevtxlen && ok; j++)
            if (fprintf(f, "%02x", u->prevtx[j]) < 0) ok = 0;
        if (ok && fprintf(f, "\n") < 0) ok = 0;
    }

    for (i = 0; i < us->count && ok; i++) {
        const kw_utxo *u = &us->u[i];
        char txid[65], spk[2 * KW_SPK_MAX + 1];

        if (!kw_hex_encode(u->txid, 32, txid, sizeof txid) ||
            !kw_hex_encode(u->spk, u->spklen, spk, sizeof spk)) { ok = 0; break; }
        if (fprintf(f, "u %s %u %llu %u %s%s\n", txid, u->vout,
                    (unsigned long long)u->value, u->height, spk,
                    u->coinbase ? " c" : "") < 0) ok = 0;
    }

    /* The count last, so a file that was cut short cannot load as a smaller
       balance. A line boundary or an even number of script bytes both parse. */
    if (ok && fprintf(f, "# end %llu\n", (unsigned long long)us->count) < 0) ok = 0;
    return commit_temp(f, tmp, path, ok);
}

int kw_scanmeta_write(const char *utxos_path, int64_t feerate, int extent, uint32_t tip)
{
    char p[4200], tmp[4300];
    if ((size_t)snprintf(p, sizeof p, "%s.meta", utxos_path) >= sizeof p) return 0;
    FILE *f = open_private_temp(p, tmp, sizeof tmp);
    if (!f) return 0;
    int ok = fprintf(f, "feerate %lld\ngap %d\ntip %u\n",
                     (long long)feerate, extent, tip) > 0;
    return commit_temp(f, tmp, p, ok);
}

void kw_scanmeta_read(const char *utxos_path, int64_t *feerate, int *extent, uint32_t *tip)
{
    if (feerate) *feerate = 0;
    if (extent) *extent = 0;
    if (tip) *tip = 0;
    char p[4200];
    snprintf(p, sizeof p, "%s.meta", utxos_path);
    FILE *f = fopen(p, "r");
    if (!f) return;
    char key[32]; long long v;
    while (fscanf(f, "%31s %lld", key, &v) == 2) {
        if (!strcmp(key, "feerate") && feerate) *feerate = (int64_t)v;
        else if (!strcmp(key, "gap") && extent) *extent = (int)v;
        else if (!strcmp(key, "tip") && tip && v >= 0) *tip = (uint32_t)v;
    }
    fclose(f);
}

/* A transaction read off a "t" line, held until the "u" lines that name it. */
struct prevtx {
    uint8_t  txid[32];
    uint8_t *raw;
    size_t   len;
};

static void prevtx_free(struct prevtx *t, size_t n)
{
    for (size_t i = 0; i < n; i++) free(t[i].raw);
    free(t);
}

static const struct prevtx *prevtx_find(const struct prevtx *t, size_t n,
                                        const uint8_t txid[32])
{
    for (size_t i = 0; i < n; i++)
        if (memcmp(t[i].txid, txid, 32) == 0) return &t[i];
    return NULL;
}

const char *kw_utxoset_strerror(kw_utxoset_err e)
{
    switch (e) {
    case KW_UTXOSET_OK:      return "ok";
    case KW_UTXOSET_NOFILE:  return "no such file";
    case KW_UTXOSET_FORMAT:  return "not a koinu utxo set v2";
    case KW_UTXOSET_UNBOUND: return "an entry names a value its transaction does not carry";
    case KW_UTXOSET_SHORT:   return "cut short, or the count disagrees";
    case KW_UTXOSET_MEMORY:  return "out of memory";
    }
    return "unknown error";
}

int kw_utxoset_load(kw_utxoset *us, const char *path, kw_utxoset_err *why)
{
    /* Two hex characters per byte of transaction, plus the tag, the txid and a
       newline. One allocation rather than a frame this size. */
    const size_t linecap = 2 * KW_UTXO_PREVTX_MAX + 128;
    char *line = NULL;
    FILE *f = NULL;
    struct prevtx *txs = NULL;
    size_t ntx = 0, txcap = 0;
    int ok = 1, ended = 0, v2 = 0;
    unsigned long long endcount = 0, added = 0;
    kw_utxoset_err err = KW_UTXOSET_OK;

    if (why) *why = KW_UTXOSET_OK;
    f = fopen(path, "r");
    if (!f) { if (why) *why = KW_UTXOSET_NOFILE; return 0; }
    line = (char *)malloc(linecap);
    if (!line) { fclose(f); if (why) *why = KW_UTXOSET_MEMORY; return 0; }

    while (ok && fgets(line, (int)linecap, f)) {
        if (line[0] == '#') {
            if (strstr(line, "utxo set v2")) v2 = 1;
            else if (strstr(line, "utxo set v")) { ok = 0; err = KW_UTXOSET_FORMAT; break; }
            if (sscanf(line, "# end %llu", &endcount) == 1) ended = 1;
            continue;
        }
        if (line[0] == '\n') continue;
        /* A set from before the amounts were bound cannot say what its entries
           are worth, and reading it would be trusting the file. */
        if (!v2) { ok = 0; err = KW_UTXOSET_FORMAT; break; }

        if (line[0] == 't' && line[1] == ' ') {
            char txidhex[128];
            char *hex;
            size_t hl, b;

            if (sscanf(line + 2, "%127s", txidhex) != 1) { ok = 0; err = KW_UTXOSET_FORMAT; break; }
            if (strlen(txidhex) != 64) { ok = 0; err = KW_UTXOSET_FORMAT; break; }
            hex = line + 2 + 64;
            while (*hex == ' ') hex++;
            hl = strcspn(hex, " \r\n");
            if (hl == 0 || hl % 2 || hl / 2 > KW_UTXO_PREVTX_MAX) { ok = 0; err = KW_UTXOSET_FORMAT; break; }

            if (ntx == txcap) {
                size_t nc = txcap ? txcap * 2 : 16;
                struct prevtx *nt = (struct prevtx *)realloc(txs, nc * sizeof *nt);
                if (!nt) { ok = 0; err = KW_UTXOSET_MEMORY; break; }
                txs = nt; txcap = nc;
            }
            txs[ntx].raw = (uint8_t *)malloc(hl / 2);
            if (!txs[ntx].raw) { ok = 0; err = KW_UTXOSET_MEMORY; break; }
            txs[ntx].len = hl / 2;
            if (!kw_hex_decode(txidhex, 64, txs[ntx].txid, 32) ||
                !kw_hex_decode(hex, hl, txs[ntx].raw, hl / 2)) {
                free(txs[ntx].raw);
                ok = 0;
                err = KW_UTXOSET_FORMAT;
                break;
            }
            /* The txid is checked here rather than only when an entry resolves
               against it, so a file carrying a transaction that is not the one
               it is filed under is refused whether an entry names it or not. */
            {
                uint8_t h[32];
                kw_hash256(txs[ntx].raw, txs[ntx].len, h);
                if (memcmp(h, txs[ntx].txid, 32) != 0) {
                    free(txs[ntx].raw);
                    ok = 0;
                    err = KW_UTXOSET_UNBOUND;
                    break;
                }
            }
            b = ntx++;
            (void)b;
            continue;
        }

        if (line[0] != 'u' || line[1] != ' ') { ok = 0; err = KW_UTXOSET_FORMAT; break; }
        {
            /* Every conversion is width-limited, including the last: a bare %s
               here let a long line in a tampered file write past spkhex and into
               the frame. The buffer is one over the longest legitimate script so
               an overlong token comes back at full width and is refused rather
               than silently truncated into a shorter script that parses. */
            char txidhex[128], spkhex[2 * KW_SPK_MAX + 2];
            /* sscanf takes a literal width, so tie it to the buffer here: a
               change to KW_SPK_MAX becomes a build error rather than a silent
               overflow. */
            _Static_assert(2 * KW_SPK_MAX + 2 == 130, "the %129s below tracks KW_SPK_MAX");
            unsigned vout, height;
            unsigned long long value;
            /* The sixth field says whether the output is a coinbase. */
            char cbflag[8] = "";
            uint8_t txid[32], spk[KW_SPK_MAX];
            const struct prevtx *t;
            size_t spklen;
            int got, coinbase;

            got = sscanf(line + 2, "%127s %u %llu %u %129s %7s",
                         txidhex, &vout, &value, &height, spkhex, cbflag);
            if (got != 5 && got != 6) { ok = 0; err = KW_UTXOSET_FORMAT; break; }
            coinbase = (got == 6 && cbflag[0] == 'c');
            if (strlen(spkhex) > 2 * KW_SPK_MAX) { ok = 0; err = KW_UTXOSET_FORMAT; break; }
            spklen = strlen(spkhex) / 2;
            if (strlen(txidhex) != 64 || spklen == 0 || spklen > KW_SPK_MAX ||
                !kw_hex_decode(txidhex, 64, txid, 32) ||
                !kw_hex_decode(spkhex, strlen(spkhex), spk, spklen)) { ok = 0; err = KW_UTXOSET_FORMAT; break; }

            t = prevtx_find(txs, ntx, txid);
            if (!t) { ok = 0; err = KW_UTXOSET_UNBOUND; break; }
            /* kw_utxoset_add binds the value and the script to those bytes. */
            if (!kw_utxoset_add(us, txid, vout, value, height, spk, spklen, coinbase,
                                t->raw, t->len)) { ok = 0; err = KW_UTXOSET_UNBOUND; break; }
            added++;
        }
    }

    fclose(f);
    free(line);
    prevtx_free(txs, ntx);
    /* No end marker, or one that disagrees, means the file is not the whole set:
       it was cut short, or it predates the marker. Either way the balance it
       would load is not the balance, so say so instead of showing it. */
    if (ok && (!ended || endcount != added)) { ok = 0; err = KW_UTXOSET_SHORT; }
    if (!ok && err == KW_UTXOSET_OK) err = KW_UTXOSET_FORMAT;
    if (why) *why = err;
    return ok;
}
