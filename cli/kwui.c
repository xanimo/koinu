/* koinu.dog - kwui, a terminal view of a wallet
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Read-only: it opens the keystore, derives addresses, reads the utxo set kw
 * scan wrote, and draws them. It never connects to a peer and never signs, so
 * the seed it holds only ever produces addresses. Plain ANSI on termios, no
 * curses, in keeping with secp256k1 being the only dependency. */

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
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
} row;

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
            for (size_t u = 0; u < us->count; u++)
                if (us->u[u].spklen == 25 && memcmp(us->u[u].spk, spk, 25) == 0) {
                    r->balance += us->u[u].value; r->nutxo++;
                }
            *total += r->balance;
            n++;
        }
    }
    kw_secure_zero(&master, sizeof master);
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

/* One frame: a header, then the rows from (top), then the keys. (used_only)
   hides addresses the chain has never paid. */
static void draw(const kw_chainparams *cp, const row *rows, int n, int top, int sel,
                 uint64_t total, size_t nutxo, int used_only, const char *ks)
{
    printf("\033[H\033[2J");
    char bal[32]; fmt_doge(total, bal, sizeof bal);
    printf("\033[1m koinu \033[0m %s   %s\r\n", cp->name, ks);
    printf(" balance %s DOGE across %zu outputs\r\n\r\n", bal, nutxo);
    printf("  %-38s %-8s %18s %s\r\n", "address", "path", "balance", "utxos");

    int shown = 0;
    for (int i = top; i < n && shown < 15; i++) {
        if (used_only && rows[i].nutxo == 0) continue;
        char b[32]; fmt_doge(rows[i].balance, b, sizeof b);
        printf("%s %-38s %c/%-6u %18s %5d\033[0m\r\n",
               i == sel ? "\033[7m>" : " ",
               rows[i].addr, rows[i].change ? 'c' : 'r', rows[i].index,
               b, rows[i].nutxo);
        shown++;
    }
    if (!shown) printf("  (no addresses to show; run kw scan to fill the utxo set)\r\n");

    printf("\r\n j/k move   u %s   q quit\r\n",
           used_only ? "show all" : "used only");
    fflush(stdout);
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

    screen_enter();
    int top = 0, sel = 0, used_only = 0, running = 1;
    while (running) {
        draw(cp, rows, n, top, sel, total, us.count, used_only, ks);
        int c = getchar();
        switch (c) {
        case 'q': case 3: case EOF: running = 0; break;
        case 'j': if (sel < n - 1) sel++; break;
        case 'k': if (sel > 0) sel--; break;
        case 'u': used_only = !used_only; top = 0; sel = 0; break;
        case '\033':                       /* arrow keys arrive as ESC [ A/B */
            if (getchar() == '[') {
                int d = getchar();
                if (d == 'B' && sel < n - 1) sel++;
                if (d == 'A' && sel > 0) sel--;
            }
            break;
        default: break;
        }
        if (sel < top) top = sel;
        if (sel > top + 14) top = sel - 14;
    }
    screen_leave();

    free(rows);
    kw_utxoset_free(&us);
    kw_ec_stop();
    return 0;
}
