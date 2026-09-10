/* koinu.dog - kwui, a terminal view of a wallet
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * It opens the keystore, derives addresses, reads the utxo set kw scan wrote,
 * and draws them; s composes a spend, confirms it, and signs it. It never
 * opens a socket: the signed transaction is written out for kw send, so the
 * process holding keys is not the process talking to peers. The seed is not
 * kept while browsing, so signing asks for the passphrase again. Plain ANSI on
 * termios, no curses, in keeping with secp256k1 being the only dependency. */

#include "chainparams.h"
#include "keystore.h"
#include "bip32.h"
#include "bip44.h"
#include "address.h"
#include "ripemd160.h"
#include "ec.h"
#include "hex.h"
#include "mem.h"
#include "utxo.h"
#include "tx.h"
#include "bip39.h"
#include "base58.h"
#include "fee.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define MAXADDR 200

static const kw_chainparams *chain_for(int net)
{
    if (net == 1) return &KW_DOGE_TESTNET;
    if (net == 2) return &KW_DOGE_REGTEST;
    return &KW_DOGE_MAINNET;
}

/* koinu to a DOGE string, no floating point */
static void fmt_doge(uint64_t v, char *out, size_t cap)
{
    snprintf(out, cap, "%llu.%08llu",
             (unsigned long long)(v / 100000000ULL),
             (unsigned long long)(v % 100000000ULL));
}

static void h160_to_spk(const uint8_t h160[20], uint8_t spk[25])
{
    spk[0]=0x76; spk[1]=0xa9; spk[2]=0x14; memcpy(spk+3, h160, 20); spk[23]=0x88; spk[24]=0xac;
}

/* Read a passphrase without echo. Never taken from argv, where ps could see it. */
static char *ask_pass(void)
{
    struct termios old, quiet;
    int tty = isatty(STDIN_FILENO);
    fprintf(stderr, "passphrase: ");
    if (tty) {
        tcgetattr(STDIN_FILENO, &old); quiet = old;
        quiet.c_lflag &= ~(tcflag_t)ECHO;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &quiet);
    }
    char *line = NULL; size_t cap = 0;
    ssize_t n = getline(&line, &cap, stdin);
    if (tty) { tcsetattr(STDIN_FILENO, TCSAFLUSH, &old); fprintf(stderr, "\n"); }
    if (n < 0) { free(line); return NULL; }
    while (n && (line[n-1] == '\n' || line[n-1] == '\r')) line[--n] = '\0';
    return line;
}

typedef struct {
    char     addr[64];
    uint32_t change, index;
    uint64_t balance;
    int      nutxo;
    uint8_t  spk[25];
} row;

/* decimal DOGE to koinu, no floating point */
static int parse_doge(const char *str, uint64_t *out)
{
    uint64_t whole = 0, frac = 0; int digits = 0, seen = 0;
    const char *q = str;
    for (; *q && *q != '.'; q++) {
        if (*q < '0' || *q > '9') return 0;
        if (whole > (UINT64_MAX - 9) / 10) return 0;
        whole = whole * 10 + (uint64_t)(*q - '0'); seen = 1;
    }
    if (*q == '.') {
        for (q++; *q; q++) {
            if (*q < '0' || *q > '9' || digits >= 8) return 0;
            frac = frac * 10 + (uint64_t)(*q - '0'); digits++; seen = 1;
        }
    }
    if (!seen) return 0;
    while (digits++ < 8) frac *= 10;
    *out = whole * 100000000ULL + frac;
    return 1;
}

/* Total what the utxo set pays each row. Separate from deriving the rows because
   a refresh re-tallies and derives nothing, so it needs no seed: the addresses
   are already in hand and only what the chain pays them has moved. */
static uint64_t tally_rows(const kw_utxoset *us, row *rows, int n)
{
    uint64_t total = 0;
    for (int i = 0; i < n; i++) {
        rows[i].balance = 0;
        rows[i].nutxo = 0;
        for (size_t u = 0; u < us->count; u++)
            if (us->u[u].spklen == 25 && memcmp(us->u[u].spk, rows[i].spk, 25) == 0) {
                rows[i].balance += us->u[u].value;
                rows[i].nutxo++;
            }
        total += rows[i].balance;
    }
    return total;
}

/* Derive (gap) receive then (gap) change addresses and total what the utxo set
   pays each, so a row is an address and what it holds. */
static int build_rows(const kw_chainparams *cp, const uint8_t seed[64], int gap,
                      const kw_utxoset *us, row *rows, int cap, uint64_t *total)
{
    kw_bip32_key master;
    if (!kw_bip32_from_seed(seed, 64, cp->bip32, &master)) return 0;

    int n = 0;
    *total = 0;
    for (uint32_t change = 0; change < 2; change++) {
        for (int i = 0; i < gap && n < cap; i++) {
            kw_bip32_key key;
            if (!kw_bip44_derive(&master, cp->bip44_coin, 0, change, (uint32_t)i, &key)) continue;
            uint8_t pub[33], h160[20], spk[25];
            kw_bip32_pubkey(&key, pub);
            kw_hash160(pub, 33, h160);
            h160_to_spk(h160, spk);
            kw_secure_zero(&key, sizeof key);

            row *r = &rows[n];
            memset(r, 0, sizeof *r);
            if (!kw_address_p2pkh(pub, cp->p2pkh, r->addr, sizeof r->addr)) continue;
            r->change = change; r->index = (uint32_t)i;
            memcpy(r->spk, spk, 25);
            n++;
        }
    }
    kw_secure_zero(&master, sizeof master);
    *total = tally_rows(us, rows, n);
    return n;
}

static struct termios g_saved;
static int g_raw = 0;

static void screen_leave(void)
{
    if (g_raw) tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_saved);
    printf("\033[?25h\033[?1049l");            /* cursor back, primary screen */
    fflush(stdout);
}

static void screen_enter(void)
{
    if (tcgetattr(STDIN_FILENO, &g_saved) == 0) {
        struct termios raw = g_saved;
        raw.c_lflag &= ~(tcflag_t)(ECHO | ICANON);
        raw.c_cc[VMIN] = 1; raw.c_cc[VTIME] = 0;
        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) == 0) g_raw = 1;
    }
    printf("\033[?1049h\033[?25l");            /* alternate screen, hide cursor */
}

/* How many rows fit, from the terminal rather than a guess. Asked every frame,
   which is how a resize is handled without a signal handler. */
static int page_rows(void)
{
    struct winsize w;
    int h = 24;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0 && w.ws_row > 0) h = w.ws_row;
    h -= 8;                                     /* header, column titles, key line */
    return h < 1 ? 1 : h;
}

/* One frame. (vis) holds the indices of the rows to show, so (top) and (sel)
   index what is on screen and not the unfiltered array: with the filter on, a
   selection into the array could land on a hidden row. */
static void draw(const kw_chainparams *cp, const row *rows, const int *vis, int nvis,
                 int top, int sel, uint64_t total, size_t nutxo, int used_only,
                 const char *ks)
{
    printf("\033[H\033[2J");
    char bal[32]; fmt_doge(total, bal, sizeof bal);
    printf("\033[1m koinu \033[0m %s   %s\r\n", cp->name, ks);
    printf(" balance %s DOGE across %zu outputs\r\n\r\n", bal, nutxo);
    printf("  %-38s %-8s %18s %s\r\n", "address", "path", "balance", "utxos");

    int per = page_rows(), shown = 0;
    for (int v = top; v < nvis && shown < per; v++, shown++) {
        const row *r = &rows[vis[v]];
        char b[32]; fmt_doge(r->balance, b, sizeof b);
        printf("%s %-38s %c/%-6u %18s %5d\033[0m\r\n",
               v == sel ? "\033[7m>" : " ",
               r->addr, r->change ? 'c' : 'r', r->index, b, r->nutxo);
    }
    if (!shown) printf("  (no addresses to show; run kw scan to fill the utxo set)\r\n");

    printf("\r\n j/k move   enter address   c coins   u %s   r refresh   s send   q quit\r\n",
           used_only ? "show all" : "used only");
    fflush(stdout);
}


/* Display order for a txid, abbreviated: eight bytes are enough to find a
   transaction in an explorer and 64 characters do not fit a column. */
static void txid_short(const uint8_t txid[32], char *out, size_t cap)
{
    uint8_t d[32];
    char full[65];
    for (int i = 0; i < 32; i++) d[i] = txid[31 - i];
    kw_hex_encode(d, 32, full, sizeof full);
    snprintf(out, cap, "%.16s..", full);
}

/* Does this output pay (spk)? p2pkh only, which is all a row can be. */
static int pays(const kw_utxo *u, const uint8_t spk[25])
{
    return u->spklen == 25 && memcmp(u->spk, spk, 25) == 0;
}

/* One address in full, its path, and the outputs paying it. This is the receive
   screen as well: an unused receive row is what you hand to whoever is paying,
   so the address is on its own line to be read out or copied without the
   surrounding columns getting in the way. */
static void addr_view(const kw_chainparams *cp, const row *r, const kw_utxoset *us)
{
    int top = 0;
    for (;;) {
        int nmine = 0;
        for (size_t u = 0; u < us->count; u++) if (pays(&us->u[u], r->spk)) nmine++;

        int per = page_rows() - 4;
        if (per < 1) per = 1;
        if (top > nmine - per) top = nmine - per;
        if (top < 0) top = 0;

        char b[32];
        fmt_doge(r->balance, b, sizeof b);
        printf("\033[H\033[2J\033[1m %s address\033[0m   %s\r\n\r\n",
               r->change ? "change" : "receive", cp->name);
        printf("   \033[1m%s\033[0m\r\n\r\n", r->addr);
        printf("   path      m/44'/%u'/0'/%u/%u\r\n", cp->bip44_coin, r->change, r->index);
        printf("   holds     %s DOGE across %d output(s)\r\n\r\n", b, r->nutxo);

        if (!nmine) {
            printf("   nothing has paid it yet%s\r\n",
                   r->change ? "" : ", so it is safe to hand out");
        } else {
            printf("   %-8s %-20s %6s %18s\r\n", "height", "txid", "vout", "value");
            int shown = 0, seen = 0;
            for (size_t u = 0; u < us->count && shown < per; u++) {
                if (!pays(&us->u[u], r->spk)) continue;
                if (seen++ < top) continue;
                char t[32], v[32];
                txid_short(us->u[u].txid, t, sizeof t);
                fmt_doge(us->u[u].value, v, sizeof v);
                printf("   %-8u %-20s %6u %18s\r\n", us->u[u].height, t, us->u[u].vout, v);
                shown++;
            }
            if (nmine > per)
                printf("\r\n   showing %d..%d of %d\r\n", top + 1, top + shown, nmine);
        }
        printf("\r\n j/k scroll   q back\r\n");
        fflush(stdout);

        int c = getchar();
        if (c == 'q' || c == '\n' || c == '\r' || c == 3 || c == EOF) return;
        if (c == 'j' && top + per < nmine) top++;
        if (c == 'k' && top > 0) top--;
        if (c == '\033' && getchar() == '[') {
            int d = getchar();
            if (d == 'B' && top + per < nmine) top++;
            if (d == 'A' && top > 0) top--;
        }
    }
}

/* Every output the wallet holds, newest first, with the address it pays. This is
   what the stored set can answer: these are unspent receives. A spend leaves no
   record anywhere, so it is not a transaction history and is not called one. */
struct coin { uint32_t height; size_t at; };

static int by_height_desc(const void *a, const void *b)
{
    const struct coin *x = a, *y = b;
    if (x->height != y->height) return x->height < y->height ? 1 : -1;
    return x->at < y->at ? -1 : (x->at > y->at);
}

static void coins_view(const kw_utxoset *us, const row *rows, int nrows)
{
    struct coin *c = us->count ? (struct coin *)calloc(us->count, sizeof *c) : NULL;
    if (us->count && !c) return;
    for (size_t u = 0; u < us->count; u++) { c[u].height = us->u[u].height; c[u].at = u; }
    if (us->count) qsort(c, us->count, sizeof *c, by_height_desc);

    int top = 0;
    for (;;) {
        int n = (int)us->count, per = page_rows() - 1;
        if (per < 1) per = 1;
        if (top > n - per) top = n - per;
        if (top < 0) top = 0;

        printf("\033[H\033[2J\033[1m coins\033[0m   %d unspent output(s), newest first\r\n\r\n", n);
        printf("   %-8s %-20s %6s %18s %s\r\n", "height", "txid", "vout", "value", "address");
        for (int i = top; i < n && i < top + per; i++) {
            const kw_utxo *u = &us->u[c[i].at];
            const char *addr = "(not a watched address)";
            for (int r = 0; r < nrows; r++) if (pays(u, rows[r].spk)) { addr = rows[r].addr; break; }
            char t[32], v[32];
            txid_short(u->txid, t, sizeof t);
            fmt_doge(u->value, v, sizeof v);
            printf("   %-8u %-20s %6u %18s %s\r\n", u->height, t, u->vout, v, addr);
        }
        if (!n) printf("   nothing yet; run kw scan to fill the utxo set\r\n");
        else if (n > per) printf("\r\n   showing %d..%d of %d\r\n", top + 1,
                                 top + (n - top < per ? n - top : per), n);
        printf("\r\n j/k scroll   q back\r\n");
        fflush(stdout);

        int k = getchar();
        if (k == 'q' || k == '\n' || k == '\r' || k == 3 || k == EOF) break;
        if (k == 'j' && top + per < n) top++;
        if (k == 'k' && top > 0) top--;
        if (k == '\033' && getchar() == '[') {
            int d = getchar();
            if (d == 'B' && top + per < n) top++;
            if (d == 'A' && top > 0) top--;
        }
    }
    free(c);
}

/* Read a line in cooked mode, so the terminal handles editing. */
static int ask_line(const char *prompt, char *out, size_t cap)
{
    if (g_raw) tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_saved);
    printf("\033[?25h%s", prompt); fflush(stdout);
    char *line = NULL; size_t lc = 0;
    ssize_t n = getline(&line, &lc, stdin);
    if (n > 0) { while (n && (line[n-1]=='\n'||line[n-1]=='\r')) line[--n]='\0';
                 snprintf(out, cap, "%s", line); }
    free(line);
    printf("\033[?25l");
    if (g_raw) {
        struct termios raw = g_saved;
        raw.c_lflag &= ~(tcflag_t)(ECHO | ICANON);
        raw.c_cc[VMIN] = 1; raw.c_cc[VTIME] = 0;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
    }
    return n > 0;
}

/* an address to its p2pkh or p2sh scriptPubKey on this network */
static int addr_to_spk(const kw_chainparams *cp, const char *addr, uint8_t *out, size_t *len)
{
    uint8_t pay[64]; size_t pl = 0;
    if (!kw_base58check_decode(addr, pay, sizeof pay, &pl) || pl != 21) return 0;
    if (pay[0] == cp->p2pkh) { h160_to_spk(pay + 1, out); *len = 25; return 1; }
    if (pay[0] == cp->p2sh) {
        out[0]=0xa9; out[1]=0x14; memcpy(out+2, pay+1, 20); out[22]=0x87; *len = 23; return 1;
    }
    return 0;
}

/* Compose, confirm and sign a spend. Never touches the network: the signed
   transaction is written out for kw send, so the process holding keys is not
   the process talking to peers. The seed is not kept while browsing, so the
   passphrase is asked for again here, which is also the last confirmation. */
static void send_flow(const kw_chainparams *cp, const char *ks, const char *utxos,
                      const kw_utxoset *us, const row *rows, int nrows)
{
    char to[128] = "", amt[64] = "";
    if (!ask_line("\r\nto address: ", to, sizeof to) || !to[0]) return;
    uint8_t dspk[25]; size_t dl = 0;
    if (!addr_to_spk(cp, to, dspk, &dl)) {
        ask_line("not an address on this network. enter to go back ", amt, sizeof amt);
        return;
    }
    if (!ask_line("amount in DOGE: ", amt, sizeof amt)) return;
    uint64_t want = 0;
    if (!parse_doge(amt, &want) || want < 1000000ULL) {
        ask_line("amount is not a number, or below the 0.01 dust limit. enter to go back ", to, sizeof to);
        return;
    }

    /* Oldest first, so mature coinbase goes before recent change. (used) is
       allocated rather than fixed: a wallet with more outputs than the array
       would otherwise have the rest treated as absent, refusing a spend it can
       afford. */
    int order[KW_TX_MAX_IN]; int nin = 0;
    uint64_t in_total = 0, fee = 0;
    char *used = us->count ? (char *)calloc(us->count, 1) : NULL;
    if (us->count && !used) {
        ask_line("   out of memory. enter to go back ", to, sizeof to);
        return;
    }
    while (nin < KW_TX_MAX_IN) {
        int pick = -1;
        uint32_t best_h = 0xffffffffu;
        for (size_t u = 0; u < us->count; u++)
            if (!used[u] && us->u[u].spklen == 25 && us->u[u].height <= best_h) {
                best_h = us->u[u].height; pick = (int)u;
            }
        if (pick < 0) break;
        used[pick] = 1; order[nin++] = pick;
        in_total += us->u[pick].value;
        fee = kw_est_fee(nin, 2, KW_MIN_RELAY_FEE_PER_KB);
        if (in_total >= want + fee) break;
    }
    free(used);
    if (in_total < want + fee) {
        char m[160]; char b[32]; fmt_doge(in_total, b, sizeof b);
        snprintf(m, sizeof m, "only %s DOGE selectable, need more. enter to go back ", b);
        ask_line(m, to, sizeof to);
        return;
    }
    uint64_t change = in_total - want - fee;
    int with_change = change >= 1000000ULL;
    if (!with_change) { fee += change; change = 0; }   /* dust change goes to fee */

    /* the ceiling kw send applies, applied here too: signing from a screen is
       the path least likely to have the number read twice */
    size_t nbytes = kw_est_size(nin, with_change ? 2 : 1);
    if (fee > kw_fee_cap(nbytes)) {
        char m[200], bf[32], bcap[32];
        fmt_doge(fee, bf, sizeof bf);
        fmt_doge(kw_fee_cap(nbytes), bcap, sizeof bcap);
        snprintf(m, sizeof m, "   fee %s DOGE is over the %s DOGE limit for about %zu bytes."
                              " enter to go back ", bf, bcap, nbytes);
        ask_line(m, to, sizeof to);
        return;
    }

    char bw[32], bf[32], bc[32], bt[32];
    fmt_doge(want, bw, sizeof bw); fmt_doge(fee, bf, sizeof bf);
    fmt_doge(change, bc, sizeof bc); fmt_doge(in_total, bt, sizeof bt);
    printf("\033[H\033[2J\033[1m confirm this spend\033[0m\r\n\r\n");
    printf("   to        %s\r\n", to);
    printf("   amount    %s DOGE\r\n", bw);
    printf("   fee       %s DOGE\r\n", bf);
    printf("   change    %s DOGE%s\r\n", bc, with_change ? "" : "  (below dust, added to the fee)");
    printf("   spending  %s DOGE across %d output(s)\r\n\r\n", bt, nin);
    printf("   nothing is broadcast: the signed transaction is written out\r\n");
    printf("   for kw send, and can be discarded until then.\r\n\r\n");
    fflush(stdout);

    char yes[16] = "";
    if (!ask_line("   type yes to sign, anything else to cancel: ", yes, sizeof yes) ||
        strcmp(yes, "yes") != 0) return;

    /* re-open the keystore: the seed is not held while browsing */
    uint8_t blob[8192]; size_t bn = 0;
    FILE *f = fopen(ks, "rb");
    if (!f) return;
    bn = fread(blob, 1, sizeof blob, f);
    fclose(f);
    char *pass = ask_pass();
    if (!pass) return;
    uint8_t seed[64]; size_t slen = 0;
    int opened = kw_keystore_open(blob, bn, pass, seed, sizeof seed, &slen);
    kw_secure_zero(pass, strlen(pass)); free(pass);
    kw_secure_zero(blob, sizeof blob);
    if (!opened || slen != 64) {
        ask_line("   wrong passphrase. enter to go back ", yes, sizeof yes);
        return;
    }

    kw_tx tx; kw_tx_init(&tx);
    for (int i = 0; i < nin; i++) {
        const kw_utxo *u = &us->u[order[i]];
        char disp[65]; uint8_t d[32];
        for (int b = 0; b < 32; b++) d[b] = u->txid[31 - b];
        kw_hex_encode(d, 32, disp, sizeof disp);
        kw_tx_add_input(&tx, disp, u->vout);
    }
    kw_tx_add_output(&tx, want, dspk, dl);
    if (with_change) {
        int ci = -1;
        for (int i = 0; i < nrows; i++)                  /* first unused change address */
            if (rows[i].change == 1 && rows[i].nutxo == 0) { ci = i; break; }
        if (ci < 0) for (int i = 0; i < nrows; i++) if (rows[i].change == 1) { ci = i; break; }
        if (ci >= 0) kw_tx_add_output(&tx, change, rows[ci].spk, 25);
    }

    kw_bip32_key master;
    int ok = kw_bip32_from_seed(seed, 64, cp->bip32, &master);
    for (int i = 0; i < nin && ok; i++) {
        const kw_utxo *u = &us->u[order[i]];
        int ri = -1;
        for (int r = 0; r < nrows; r++)
            if (memcmp(rows[r].spk, u->spk, 25) == 0) { ri = r; break; }
        if (ri < 0) { ok = 0; break; }
        kw_bip32_key key;
        if (!kw_bip44_derive(&master, cp->bip44_coin, 0, rows[ri].change, rows[ri].index, &key)) { ok = 0; break; }
        ok = kw_tx_sign_p2pkh(&tx, (size_t)i, key.key + 1, u->spk, 25);   /* 0x00 || d */
        kw_secure_zero(&key, sizeof key);
    }
    kw_secure_zero(&master, sizeof master);
    kw_secure_zero(seed, sizeof seed);
    if (!ok) { ask_line("   signing failed. enter to go back ", yes, sizeof yes); return; }

    uint8_t raw[16384];
    size_t rn = kw_tx_serialize(&tx, raw, sizeof raw);
    char path[4300];
    snprintf(path, sizeof path, "%s.tx", utxos);
    /* O_EXCL and 0600, as kw does for a keystore: a signed spend that has not
       been broadcast is not something to overwrite, and it authorises a payment
       until it is. */
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        char m[4400];
        snprintf(m, sizeof m, "   %s already exists, so nothing was written."
                              " broadcast or remove it first. enter to go back ", path);
        ask_line(m, yes, sizeof yes);
        return;
    }
    FILE *o = fdopen(fd, "w");
    if (!o) close(fd);
    if (rn && o) {
        char *hex = (char *)malloc(rn * 2 + 2);
        if (hex) { kw_hex_encode(raw, rn, hex, rn * 2 + 1); fprintf(o, "%s\n", hex); free(hex); }
        fclose(o);
        char m[9000];
        snprintf(m, sizeof m, "\r\n   signed, %zu bytes, written to %s\r\n"
                              "   broadcast with: kw send --tx @%s --node NODE\r\n"
                              "   enter to go back ", rn, path, path);
        ask_line(m, yes, sizeof yes);
    } else {
        if (o) fclose(o);
        ask_line("   could not write the transaction. enter to go back ", yes, sizeof yes);
    }
}

int main(int argc, char **argv)
{
    int net = 0, gap = 20;
    const char *ks = NULL, *utxos = NULL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if      (!strcmp(a, "--testnet")) net = 1;
        else if (!strcmp(a, "--regtest")) net = 2;
        else if (!strcmp(a, "--keystore") && i + 1 < argc) ks = argv[++i];
        else if (!strcmp(a, "--utxos") && i + 1 < argc)    utxos = argv[++i];
        else if (!strcmp(a, "--gap") && i + 1 < argc)      gap = atoi(argv[++i]);
        else {
            fprintf(stderr, "usage: kwui [--testnet|--regtest] --keystore PATH"
                            " [--utxos PATH] [--gap N]\n");
            return 2;
        }
    }
    if (!ks) { fprintf(stderr, "kwui: --keystore is required\n"); return 2; }
    if (gap < 1) gap = 1;
    if (gap > MAXADDR / 2) gap = MAXADDR / 2;
    const kw_chainparams *cp = chain_for(net);
    if (!kw_ec_start()) { fprintf(stderr, "kwui: ec init failed\n"); return 1; }   /* derivation needs it */

    uint8_t blob[8192]; size_t bn = 0;
    FILE *f = fopen(ks, "rb");
    if (!f) { fprintf(stderr, "kwui: cannot open %s\n", ks); return 1; }
    bn = fread(blob, 1, sizeof blob, f);
    fclose(f);

    char *pass = ask_pass();
    if (!pass) { fprintf(stderr, "kwui: no passphrase\n"); return 1; }
    uint8_t seed[64]; size_t slen = 0;
    int opened = kw_keystore_open(blob, bn, pass, seed, sizeof seed, &slen);
    kw_secure_zero(pass, strlen(pass)); free(pass);
    kw_secure_zero(blob, sizeof blob);
    if (!opened || slen != 64) { fprintf(stderr, "kwui: wrong passphrase or corrupt keystore\n"); return 1; }

    char defpath[4200];
    if (!utxos) { snprintf(defpath, sizeof defpath, "%s.utxos", ks); utxos = defpath; }
    kw_utxoset us; kw_utxoset_init(&us);
    kw_utxoset_load(&us, utxos);          /* absent is not fatal: no coins yet */

    row *rows = (row *)calloc(MAXADDR, sizeof *rows);
    if (!rows) { kw_utxoset_free(&us); kw_secure_zero(seed, sizeof seed); return 1; }
    uint64_t total = 0;
    int n = build_rows(cp, seed, gap, &us, rows, MAXADDR, &total);
    kw_secure_zero(seed, sizeof seed);     /* addresses are derived; the seed is done */

    int *vis = (int *)calloc((size_t)(n > 0 ? n : 1), sizeof *vis);
    if (!vis) { free(rows); kw_utxoset_free(&us); kw_ec_stop(); return 1; }

    screen_enter();
    int top = 0, sel = 0, used_only = 0, running = 1;
    while (running) {
        int nvis = 0;
        for (int i = 0; i < n; i++) if (!used_only || rows[i].nutxo) vis[nvis++] = i;
        if (sel >= nvis) sel = nvis ? nvis - 1 : 0;

        draw(cp, rows, vis, nvis, top, sel, total, us.count, used_only, ks);
        int c = getchar();
        switch (c) {
        case 'q': case 3: case EOF: running = 0; break;
        case 'j': if (sel < nvis - 1) sel++; break;
        case 'k': if (sel > 0) sel--; break;
        case 'u': used_only = !used_only; top = 0; sel = 0; break;
        case 'r': {
            /* kw scan writes the file this reads, so a refresh is a reload. Into
               a fresh set, since load appends, and the old one is only dropped
               once the new one is read: a truncated file leaves what was there. */
            kw_utxoset fresh;
            if (!kw_utxoset_init(&fresh)) break;
            if (kw_utxoset_load(&fresh, utxos)) {
                kw_utxoset_free(&us);
                us = fresh;
                total = tally_rows(&us, rows, n);
            } else {
                kw_utxoset_free(&fresh);
            }
            break;
        }
        case 's': send_flow(cp, ks, utxos, &us, rows, n); break;
        case 'c': coins_view(&us, rows, n); break;
        case '\n': case '\r':
            if (nvis) addr_view(cp, &rows[vis[sel]], &us);
            break;
        case '\033':                       /* arrow keys arrive as ESC [ A/B */
            if (getchar() == '[') {
                int d = getchar();
                if (d == 'B' && sel < nvis - 1) sel++;
                if (d == 'A' && sel > 0) sel--;
            }
            break;
        default: break;
        }
        int per = page_rows();
        if (sel < top) top = sel;
        if (sel > top + per - 1) top = sel - per + 1;
        if (top < 0) top = 0;
    }
    screen_leave();
    free(vis);

    free(rows);
    kw_utxoset_free(&us);
    kw_ec_stop();
    return 0;
}
