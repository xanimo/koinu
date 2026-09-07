/* koinu.dog - kw, a thin cli over libkw
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * The library owns the crypto, keys and wallet state; this only parses
 * arguments, does file i/o, and reads passphrases without letting them touch
 * argv. The keystore holds the 64-byte bip39 seed; the mnemonic is shown once
 * at creation for the operator to back up and is never stored. */

#include "chainparams.h"
#include "bip39.h"
#include "bip32.h"
#include "bip44.h"
#include "address.h"
#include "base58.h"
#include "keystore.h"
#include "ripemd160.h"
#include "sha2.h"
#include "tx.h"
#include "hex.h"
#include "ec.h"
#include "mem.h"
#include "peer.h"
#include "sync.h"
#include "spv.h"
#include "cf.h"
#include "utxo.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

static void usage(void)
{
    fprintf(stderr,
      "usage: kw [--testnet|--regtest] <command> [options]\n"
      "\n"
      "  new      --keystore PATH [--passphrase @FILE|-] [--words 12|24]\n"
      "  restore  --keystore PATH [--passphrase @FILE|-] [--mnemonic @FILE|-]\n"
      "  address  --keystore PATH [--passphrase @FILE|-] [--account N]\n"
      "                                          [--index N] [--change]\n"
      "  scan     --keystore PATH [--passphrase @FILE|-] --node HOST [--port N]\n"
      "           [--tor] [--cf|--spv] [--gap N] [--utxos PATH]\n"
      "  sign     --keystore PATH [--passphrase @FILE|-] --to ADDR:AMOUNT\n"
      "           [--fee DOGE | --feerate DOGE_PER_KB] [--change-to ADDR]\n"
      "           [--gap N] [--utxos PATH] [--input TXID:VOUT:AMOUNT:INDEX ...]\n"
      "  sweep    --wif @FILE|- --to ADDR --node HOST [--port N] [--tor]\n"
      "           [--cf|--spv] [--fee DOGE | --feerate DOGE_PER_KB]\n"
      "  height   --node HOST [--port N] [--tor]\n"
      "  outpoint --watch ADDR|SPKHEX --outpoint TXID:VOUT --node HOST\n"
      "           [--port N] [--tor] [--cf|--spv]\n"
      "  send     --tx HEX|@FILE|- --node HOST [--port N] [--tor]\n"
      "\n"
      "  --headers PATH caches the header chain for scan, height and outpoint, so\n"
      "  a later run resumes from the stored tip instead of syncing from genesis.\n"
      "  --filters PATH (with --cf) caches basic filters, so scan and outpoint test\n"
      "  them locally and download only matching blocks; the first run fills it.\n"
      "  scan watches the first --gap receive and change addresses, syncs from\n"
      "  --node (compact filters by default, --spv for full blocks), and writes the\n"
      "  utxo set to <keystore>.utxos. sign then selects inputs from it; with\n"
      "  --input it instead spends the named outpoints. The fee defaults to the\n"
      "  0.001 DOGE/kB relay floor; pass --feerate 0.01 for the miner-preferred\n"
      "  rate, or --fee for an exact amount.\n"
      "\n"
      "  A passphrase or mnemonic is read from a file (@PATH), from stdin (-),\n"
      "  or prompted for; never from the command line, where ps could see it.\n"
      "  The keystore stores the seed; the mnemonic printed by new/restore is\n"
      "  the only backup and cannot be recovered from the keystore.\n");
}

/* trim a trailing newline/CR in place */
static void chomp(char *s)
{
    size_t n = strlen(s);
    while (n && (s[n-1] == '\n' || s[n-1] == '\r')) s[--n] = '\0';
}

/* Read a secret line from @FILE, stdin ("-"), or a no-echo prompt. A bare value
   is refused: it would sit in argv. Caller frees with pc-style secret wipe. */
static char *read_secret(const char *arg, const char *prompt)
{
    char *line = NULL; size_t cap = 0; ssize_t n;

    if (arg && arg[0] == '@') {
        FILE *f = fopen(arg + 1, "r");
        if (!f) return NULL;
        n = getline(&line, &cap, f);
        fclose(f);
    } else if (arg && !strcmp(arg, "-")) {
        n = getline(&line, &cap, stdin);
    } else if (arg) {
        fprintf(stderr, "kw: pass this via @FILE or - , not on the command line\n");
        return NULL;
    } else {
        struct termios old, quiet;
        int tty = isatty(STDIN_FILENO);
        fprintf(stderr, "%s", prompt);
        if (tty) { tcgetattr(STDIN_FILENO, &old); quiet = old; quiet.c_lflag &= ~(tcflag_t)ECHO;
                   tcsetattr(STDIN_FILENO, TCSAFLUSH, &quiet); }
        n = getline(&line, &cap, stdin);
        if (tty) { tcsetattr(STDIN_FILENO, TCSAFLUSH, &old); fprintf(stderr, "\n"); }
    }
    if (n < 0) { free(line); return NULL; }
    chomp(line);
    return line;
}

static void secret_free(char *s)
{
    if (!s) return;
    volatile char *p = (volatile char *)s;
    size_t n = strlen(s);
    while (n--) *p++ = 0;
    free(s);
}

static const kw_chainparams *chain_for(int net) /* 0 main, 1 test, 2 regtest */
{
    if (net == 1) return &KW_DOGE_TESTNET;
    if (net == 2) return &KW_DOGE_REGTEST;
    return &KW_DOGE_MAINNET;
}

/* Derive the seed's first-account key at (change,index) into an address. */
static int derive_address(const kw_chainparams *cp, const uint8_t seed[64],
                          uint32_t account, uint32_t change, uint32_t index,
                          char *addr, size_t addrcap)
{
    kw_bip32_key master, key;
    if (!kw_bip32_from_seed(seed, 64, cp->bip32, &master)) return 0;
    int ok = kw_bip44_derive(&master, cp->bip44_coin, account, change, index, &key);
    if (ok) {
        uint8_t pub[33], h160[20];
        kw_bip32_pubkey(&key, pub);
        kw_hash160(pub, 33, h160);
        ok = kw_address_p2pkh(pub, cp->p2pkh, addr, addrcap) != 0;
    }
    kw_secure_zero(&master, sizeof master);
    kw_secure_zero(&key, sizeof key);
    return ok;
}

/* change below this is folded into the fee rather than made into an output */
#define KOINU_DUST 1000000ULL   /* 0.01 DOGE */

/* decimal DOGE (up to 8 places) to koinu, without floating point */
static int parse_doge(const char *s, uint64_t *out)
{
    uint64_t whole = 0, frac = 0; int digits = 0, seen = 0;
    const char *p = s;
    for (; *p && *p != '.'; p++) {
        if (*p < '0' || *p > '9') return 0;
        if (whole > (UINT64_MAX - 9) / 10) return 0;
        whole = whole * 10 + (uint64_t)(*p - '0'); seen = 1;
    }
    if (*p == '.') for (p++; *p; p++) {
        if (*p < '0' || *p > '9') return 0;
        if (digits == 8) return 0;
        frac = frac * 10 + (uint64_t)(*p - '0'); digits++; seen = 1;
    }
    if (!seen) return 0;
    while (digits++ < 8) frac *= 10;
    if (whole > UINT64_MAX / 100000000ULL) return 0;
    uint64_t v = whole * 100000000ULL;
    if (v > UINT64_MAX - frac) return 0;
    *out = v + frac;
    return 1;
}

/* Dogecoin's minrelaytxfee: the lowest rate a default node will relay. The
   recommended (mined) rate is ten times this. Both are per 1000 bytes. */
#define KW_MIN_RELAY_FEE_PER_KB   100000ULL     /* 0.001 DOGE/kB */

/* A signed p2pkh tx's size: ~148 bytes per input, 34 per output, 10 overhead.
   The input estimate rounds up (a der signature is 71-72 bytes), so the fee is
   never short. */
static uint64_t est_fee(int nin, int nout, uint64_t rate_per_kb)
{
    uint64_t size = 10 + 148ULL * (uint64_t)nin + 34ULL * (uint64_t)nout;
    return (size * rate_per_kb + 999) / 1000;    /* round up */
}

/* an address to its scriptPubKey, p2pkh or p2sh, for this network */
static int addr_to_spk(const kw_chainparams *cp, const char *addr, uint8_t *out, size_t *len)
{
    uint8_t pay[64]; size_t n = 0;
    if (!kw_base58check_decode(addr, pay, sizeof pay, &n) || n != 21) return 0;
    if (pay[0] == cp->p2pkh) {
        out[0]=0x76; out[1]=0xa9; out[2]=0x14; memcpy(out+3, pay+1, 20); out[23]=0x88; out[24]=0xac;
        *len = 25; return 1;
    }
    if (pay[0] == cp->p2sh) {
        out[0]=0xa9; out[1]=0x14; memcpy(out+2, pay+1, 20); out[22]=0x87;
        *len = 23; return 1;
    }
    return 0;
}

static int write_new_keystore(const char *path, const uint8_t *blob, size_t n)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);   /* refuse to clobber */
    if (fd < 0) { fprintf(stderr, "kw: cannot create %s (exists?)\n", path); return 0; }
    int ok = 1;
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, blob + off, n - off);
        if (w <= 0) { ok = 0; break; }
        off += (size_t)w;
    }
    close(fd);
    return ok;
}

static int read_keystore(const char *path, uint8_t *blob, size_t cap, size_t *n)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) { fprintf(stderr, "kw: cannot open %s\n", path); return 0; }
    size_t off = 0;
    for (;;) {
        ssize_t r = read(fd, blob + off, cap - off);
        if (r < 0) { close(fd); return 0; }
        if (r == 0) break;
        off += (size_t)r;
        if (off == cap) { close(fd); fprintf(stderr, "kw: keystore too large\n"); return 0; }
    }
    close(fd);
    *n = off;
    return 1;
}

/* p2pkh scriptPubKey for a hash160 */
static void h160_to_spk(const uint8_t h160[20], uint8_t spk[25])
{
    spk[0]=0x76; spk[1]=0xa9; spk[2]=0x14; memcpy(spk+3, h160, 20); spk[23]=0x88; spk[24]=0xac;
}

/* Open the keystore at (path) with the passphrase and recover the 64-byte seed. */
static int open_seed(const char *path, const char *pass_arg, uint8_t seed[64])
{
    uint8_t blob[8192]; size_t n = 0;
    if (!read_keystore(path, blob, sizeof blob, &n)) return 0;
    char *pass = read_secret(pass_arg, "passphrase: ");
    if (!pass) { fprintf(stderr, "kw: no passphrase\n"); return 0; }
    size_t slen = 0;
    int ok = kw_keystore_open(blob, n, pass, seed, 64, &slen);
    secret_free(pass);
    kw_secure_zero(blob, sizeof blob);
    if (!ok || slen != 64) { fprintf(stderr, "kw: wrong passphrase or corrupt keystore\n"); return 0; }
    return 1;
}

/* Scan metadata sits beside the utxo file: the peer's advertised feefilter (so a
   later offline sign defaults to it) and the address count scan watched (so sign
   derives far enough to key every tracked utxo). */
static void write_scan_meta(const char *utxos, int64_t feerate, int extent)
{
    char p[4200]; snprintf(p, sizeof p, "%s.meta", utxos);
    FILE *f = fopen(p, "w");
    if (f) { fprintf(f, "feerate %lld\ngap %d\n", (long long)feerate, extent); fclose(f); }
}
static void read_scan_meta(const char *utxos, int64_t *feerate, int *extent)
{
    *feerate = 0; *extent = 0;
    char p[4200]; snprintf(p, sizeof p, "%s.meta", utxos);
    FILE *f = fopen(p, "r");
    if (!f) return;
    char key[32]; long long v;
    while (fscanf(f, "%31s %lld", key, &v) == 2) {
        if (!strcmp(key, "feerate")) *feerate = (int64_t)v;
        else if (!strcmp(key, "gap")) *extent = (int)v;
    }
    fclose(f);
}

/* Init a header store, loading a cache from (path) if given so a sync resumes
   from the stored tip. A corrupt cache is ignored, not fatal. */
static void headers_open(kw_headerstore *s, const char *path)
{
    kw_headerstore_init(s);
    if (path && !kw_headerstore_load(s, path)) {
        fprintf(stderr, "kw: header cache %s is corrupt, ignoring\n", path);
        kw_headerstore_free(s);
        kw_headerstore_init(s);
    }
}

/* seal a seed under a passphrase and write it, then print the first address */
static int seal_and_report(const kw_chainparams *cp, const char *path,
                           const char *pass_arg, const uint8_t seed[64])
{
    char *pass = read_secret(pass_arg, "new passphrase: ");
    if (!pass) { fprintf(stderr, "kw: no passphrase\n"); return 1; }

    uint8_t blob[8192];
    size_t n = kw_keystore_seal(seed, 64, pass, &KW_KEYSTORE_DEFAULT, blob, sizeof blob);
    secret_free(pass);
    if (!n) { fprintf(stderr, "kw: seal failed\n"); return 1; }
    if (!write_new_keystore(path, blob, n)) { kw_secure_zero(blob, sizeof blob); return 1; }
    kw_secure_zero(blob, sizeof blob);

    char addr[128];
    if (derive_address(cp, seed, 0, 0, 0, addr, sizeof addr))
        printf("first address  %s\n", addr);
    printf("keystore       %s\n", path);
    return 0;
}

static int cmd_new(const kw_chainparams *cp, const char *path, const char *pass_arg, int words)
{
    if (!path) { usage(); return 2; }
    size_t entlen = (words == 24) ? 32 : 16;

    char mnem[KW_BIP39_MNEMONIC_MAX];
    if (!kw_bip39_generate(entlen, mnem, sizeof mnem)) { fprintf(stderr, "kw: generate failed\n"); return 1; }

    uint8_t seed[64];
    kw_bip39_to_seed(mnem, "", seed);

    printf("mnemonic (write this down, it is your only backup):\n  %s\n\n", mnem);
    kw_secure_zero(mnem, sizeof mnem);

    int rc = seal_and_report(cp, path, pass_arg, seed);
    kw_secure_zero(seed, sizeof seed);
    return rc;
}

static int cmd_restore(const kw_chainparams *cp, const char *path,
                       const char *pass_arg, const char *mnem_arg)
{
    if (!path) { usage(); return 2; }
    char *mnem = read_secret(mnem_arg, "mnemonic: ");
    if (!mnem) { fprintf(stderr, "kw: no mnemonic\n"); return 1; }
    if (!kw_bip39_check(mnem)) { secret_free(mnem); fprintf(stderr, "kw: invalid mnemonic\n"); return 1; }

    uint8_t seed[64];
    kw_bip39_to_seed(mnem, "", seed);
    secret_free(mnem);

    int rc = seal_and_report(cp, path, pass_arg, seed);
    kw_secure_zero(seed, sizeof seed);
    return rc;
}

static int cmd_address(const kw_chainparams *cp, const char *path, const char *pass_arg,
                       uint32_t account, uint32_t change, uint32_t index)
{
    if (!path) { usage(); return 2; }
    uint8_t blob[8192]; size_t n = 0;
    if (!read_keystore(path, blob, sizeof blob, &n)) return 1;

    char *pass = read_secret(pass_arg, "passphrase: ");
    if (!pass) { fprintf(stderr, "kw: no passphrase\n"); return 1; }

    uint8_t seed[64]; size_t slen = 0;
    int opened = kw_keystore_open(blob, n, pass, seed, sizeof seed, &slen);
    secret_free(pass);
    kw_secure_zero(blob, sizeof blob);
    if (!opened || slen != 64) { fprintf(stderr, "kw: wrong passphrase or corrupt keystore\n"); return 1; }

    char addr[128];
    int ok = derive_address(cp, seed, account, change, index, addr, sizeof addr);
    kw_secure_zero(seed, sizeof seed);
    if (!ok) { fprintf(stderr, "kw: derivation failed\n"); return 1; }
    printf("%s\n", addr);
    return 0;
}

/* Watch the first (gap) receive and change addresses, sync from (node), and
   write the tracked utxo set to (utxos_path) for a later sign. */
static int cmd_scan(const kw_chainparams *cp, const char *path, const char *pass_arg,
                    const char *node, int port, int tor, int use_cf, int gap,
                    const char *utxos_path, const char *headers_path, const char *filters_path)
{
    if (!path || !node) { usage(); return 2; }
    if (port <= 0) port = cp->p2p_port;
    char defpath[4096];
    if (!utxos_path) { snprintf(defpath, sizeof defpath, "%s.utxos", path); utxos_path = defpath; }

    uint8_t seed[64];
    if (!open_seed(path, pass_arg, seed)) return 1;
    kw_bip32_key master;
    int have_master = kw_bip32_from_seed(seed, 64, cp->bip32, &master);
    kw_secure_zero(seed, sizeof seed);
    if (!have_master) { fprintf(stderr, "kw: master derivation failed\n"); return 1; }

    kw_net_verbose = 1;
    kw_peer p;
    int conn = tor ? kw_peer_connect_socks5(&p, cp, node, port, 15, "127.0.0.1", 9050)
                   : kw_peer_connect(&p, cp, node, port, 15);
    if (!conn) { fprintf(stderr, "kw: connect to %s:%d failed\n", node, port); kw_secure_zero(&master, sizeof master); return 1; }

    int rc = 1;
    long nh = 0;
    int watched = gap;
    kw_utxoset us; int have_us = 0;

    if (!kw_peer_handshake(&p, 0)) { fprintf(stderr, "kw: handshake failed\n"); goto done; }

    kw_headerstore s; headers_open(&s, headers_path);
    nh = kw_sync_headers(&p, &s, cp);
    if (nh < 0) { fprintf(stderr, "kw: header sync failed\n"); kw_headerstore_free(&s); goto done; }
    if (headers_path) kw_headerstore_save(&s, headers_path);

    /* gap-limit: rescan with a growing range until `gap` unused addresses trail
       the highest used one. headers are synced once; only the scan repeats. */
    for (int iter = 0; iter < 64; iter++) {
        kw_watchset ws; kw_watchset_init(&ws);
        uint8_t (*h160map)[20] = malloc((size_t)(2 * watched) * 20);
        int *idxmap = malloc((size_t)(2 * watched) * sizeof *idxmap);
        if (!h160map || !idxmap) { free(h160map); free(idxmap); kw_watchset_free(&ws);
            fprintf(stderr, "kw: out of memory\n"); kw_headerstore_free(&s); goto done; }
        int m = 0;
        for (int chg = 0; chg <= 1; chg++)
            for (int i = 0; i < watched; i++) {
                kw_bip32_key k;
                if (kw_bip44_derive(&master, cp->bip44_coin, 0, (uint32_t)chg, (uint32_t)i, &k)) {
                    uint8_t pub[33], h[20], spk[25];
                    kw_bip32_pubkey(&k, pub); kw_hash160(pub, 33, h); h160_to_spk(h, spk);
                    kw_watchset_add(&ws, spk, 25);
                    memcpy(h160map[m], h, 20); idxmap[m] = i; m++;
                }
                kw_secure_zero(&k, sizeof k);
            }

        if (have_us) kw_utxoset_free(&us);
        kw_utxoset_init(&us); have_us = 1;
        long nb = (use_cf && filters_path) ? kw_cf_scan_cached(&p, &s, &us, &ws, 1, filters_path)
                : use_cf ? kw_cf_sync(&p, &s, &us, &ws, 1)
                : kw_spv_sync_blocks(&p, &s, &us, &ws, 1);
        kw_watchset_free(&ws);
        if (nb < 0) { free(h160map); free(idxmap);
            fprintf(stderr, "kw: %s sync failed\n", use_cf ? "filter" : "block");
            kw_headerstore_free(&s); goto done; }

        int maxidx = -1;
        for (size_t u = 0; u < us.count; u++) {
            const kw_utxo *e = &us.u[u];
            if (e->spklen != 25) continue;
            for (int t = 0; t < m; t++)
                if (memcmp(h160map[t], e->spk + 3, 20) == 0) { if (idxmap[t] > maxidx) maxidx = idxmap[t]; break; }
        }
        free(h160map); free(idxmap);

        if (watched >= maxidx + gap) break;         /* gap unused addresses trail the last used */
        fprintf(stderr, "[scan] address %d used, extending watch to %d and rescanning\n", maxidx, maxidx + gap);
        watched = maxidx + gap;
    }
    kw_headerstore_free(&s);

    if (kw_utxoset_save(&us, utxos_path)) {
        write_scan_meta(utxos_path, p.peer_feerate, watched);
        printf("scanned %ld headers, %zu utxos, balance %llu koinu\n",
               nh, kw_utxoset_count(&us), (unsigned long long)kw_utxoset_balance(&us));
        printf("watched %d addresses per chain, saved to %s\n", watched, utxos_path);
        if (p.peer_feerate > 0) printf("peer fee floor %lld koinu/kB\n", (long long)p.peer_feerate);
        rc = 0;
    } else fprintf(stderr, "kw: could not write %s\n", utxos_path);

done:
    if (have_us) kw_utxoset_free(&us);
    kw_peer_close(&p);
    kw_secure_zero(&master, sizeof master);
    return rc;
}

/* Signer. With --input, the operator names the outpoints (each owned by our key
   at m/44'/coin'/0'/0/INDEX). Without, inputs are chosen from the tracked utxo
   set written by scan, and each input's key is found by matching its script to
   a derived address in the first (gap) receive and change addresses. */
static int cmd_sign(const kw_chainparams *cp, const char *path, const char *pass_arg,
                    char **inputs, int ninputs, const char *to_arg,
                    const char *fee_arg, const char *feerate_arg, const char *change_arg,
                    const char *utxos_path, int gap)
{
    if (!path || !to_arg) { usage(); return 2; }

    uint8_t seed[64];
    if (!open_seed(path, pass_arg, seed)) return 1;

    kw_bip32_key master;
    int rc = 1;
    if (!kw_bip32_from_seed(seed, 64, cp->bip32, &master)) { kw_secure_zero(seed, sizeof seed); return 1; }

    kw_tx tx;
    kw_tx_init(&tx);
    kw_bip32_key inkeys[KW_TX_MAX_IN];
    uint8_t prevspk[KW_TX_MAX_IN][25];
    int nin = 0;
    uint64_t total_in = 0;

    kw_utxoset us; int have_us = 0;
    kw_bip32_key *keymap = NULL; uint8_t (*h160map)[20] = NULL; int keymap_n = 0;

    /* destination up front, so auto selection knows the target */
    char tob[160];
    snprintf(tob, sizeof tob, "%s", to_arg);
    char *daddr = strtok(tob, ":"), *dam = strtok(NULL, ":");
    uint64_t send_amt = 0, fee = 0;
    uint8_t dspk[25]; size_t dl = 0;
    if (!daddr || !dam || !parse_doge(dam, &send_amt)) { fprintf(stderr, "kw: bad --to, want ADDR:AMOUNT\n"); goto out; }
    if (!addr_to_spk(cp, daddr, dspk, &dl)) { fprintf(stderr, "kw: bad --to address\n"); goto out; }
    if (send_amt < KOINU_DUST) { fprintf(stderr, "kw: --to amount is below the dust limit (0.01 DOGE)\n"); goto out; }

    /* fee: an explicit --fee overrides; otherwise a rate (default the relay
       floor) times the estimated size, settled once the inputs are chosen */
    int fixed_fee = (fee_arg != NULL);
    uint64_t rate = KW_MIN_RELAY_FEE_PER_KB;
    if (fixed_fee && !parse_doge(fee_arg, &fee)) { fprintf(stderr, "kw: bad --fee\n"); goto out; }
    if (feerate_arg && !parse_doge(feerate_arg, &rate)) { fprintf(stderr, "kw: bad --feerate\n"); goto out; }

    if (ninputs > 0) {
        /* manual: the operator names each outpoint and its key index */
        for (int i = 0; i < ninputs; i++) {
            char buf[160];
            snprintf(buf, sizeof buf, "%s", inputs[i]);
            char *txid = strtok(buf, ":"), *vs = strtok(NULL, ":");
            char *as = strtok(NULL, ":"), *is = strtok(NULL, ":");
            if (!txid || !vs || !as || !is || strlen(txid) != 64) {
                fprintf(stderr, "kw: bad --input, want TXID:VOUT:AMOUNT:INDEX\n"); goto out;
            }
            uint64_t amt;
            if (!parse_doge(as, &amt)) { fprintf(stderr, "kw: bad input amount\n"); goto out; }
            uint32_t vout = (uint32_t)strtoul(vs, NULL, 10);
            uint32_t index = (uint32_t)strtoul(is, NULL, 10);
            if (!kw_bip44_derive(&master, cp->bip44_coin, 0, 0, index, &inkeys[nin])) {
                fprintf(stderr, "kw: cannot derive input %d\n", i); goto out;
            }
            uint8_t pub[33], h[20];
            kw_bip32_pubkey(&inkeys[nin], pub); kw_hash160(pub, 33, h);
            h160_to_spk(h, prevspk[nin]);
            if (!kw_tx_add_input(&tx, txid, vout)) { fprintf(stderr, "kw: too many inputs\n"); goto out; }
            total_in += amt; nin++;
        }
    } else {
        /* auto: choose coins from the tracked utxo set, keyed by hash160 of the
           first (gap) receive and change addresses */
        char defpath[4096];
        const char *up = utxos_path;
        if (!up) { snprintf(defpath, sizeof defpath, "%s.utxos", path); up = defpath; }
        kw_utxoset_init(&us); have_us = 1;
        if (!kw_utxoset_load(&us, up)) { fprintf(stderr, "kw: no utxo set at %s (run kw scan)\n", up); goto out; }

        /* scan metadata: default the rate to the peer floor it recorded, and
           derive as far as it watched so every tracked utxo's key is available */
        int64_t hint = 0; int extent = 0;
        read_scan_meta(up, &hint, &extent);
        if (!feerate_arg && hint > (int64_t)rate) rate = (uint64_t)hint;
        int derive_n = gap; if (extent > derive_n) derive_n = extent;

        keymap_n = 2 * derive_n;
        keymap = (kw_bip32_key *)malloc((size_t)keymap_n * sizeof *keymap);
        h160map = malloc((size_t)keymap_n * 20);
        if (!keymap || !h160map) { fprintf(stderr, "kw: out of memory\n"); goto out; }
        int m = 0;
        for (int chg = 0; chg <= 1; chg++)
            for (int i = 0; i < derive_n; i++) {
                if (!kw_bip44_derive(&master, cp->bip44_coin, 0, (uint32_t)chg, (uint32_t)i, &keymap[m])) continue;
                uint8_t pub[33];
                kw_bip32_pubkey(&keymap[m], pub); kw_hash160(pub, 33, h160map[m]);
                m++;
            }

        for (size_t u = 0; u < us.count; u++) {
            if (total_in >= send_amt + (fixed_fee ? fee : est_fee(nin, 2, rate))) break;
            const kw_utxo *e = &us.u[u];
            if (e->spklen != 25 || e->spk[0] != 0x76 || e->spk[1] != 0xa9 || e->spk[2] != 0x14 ||
                e->spk[23] != 0x88 || e->spk[24] != 0xac) continue;     /* only p2pkh */
            int j = -1;
            for (int t = 0; t < m; t++) if (memcmp(h160map[t], e->spk + 3, 20) == 0) { j = t; break; }
            if (j < 0) continue;                                        /* not ours within the gap */
            if (nin >= KW_TX_MAX_IN) { fprintf(stderr, "kw: too many inputs, consolidate first\n"); goto out; }
            char disphex[65]; uint8_t disp[32];
            for (int b = 0; b < 32; b++) disp[b] = e->txid[31 - b];
            kw_hex_encode(disp, 32, disphex, sizeof disphex);
            if (!kw_tx_add_input(&tx, disphex, e->vout)) { fprintf(stderr, "kw: add input\n"); goto out; }
            inkeys[nin] = keymap[j];
            memcpy(prevspk[nin], e->spk, 25);
            total_in += e->value; nin++;
        }
        uint64_t need = send_amt + (fixed_fee ? fee : est_fee(nin, 2, rate));
        if (total_in < need) {
            fprintf(stderr, "kw: insufficient funds: have %llu, need %llu koinu\n",
                    (unsigned long long)total_in, (unsigned long long)need);
            goto out;
        }
    }

    if (nin == 0) { fprintf(stderr, "kw: no inputs\n"); goto out; }

    /* settle the fee: assume a change output, then drop it (folding its value
       into the fee) when what would remain is dust */
    if (!fixed_fee) fee = est_fee(nin, 2, rate);
    if (total_in < send_amt + fee) { fprintf(stderr, "kw: inputs do not cover output plus fee\n"); goto out; }
    uint64_t change = total_in - send_amt - fee;
    if (change < KOINU_DUST && !fixed_fee) {
        fee = est_fee(nin, 1, rate);
        if (total_in < send_amt + fee) { fprintf(stderr, "kw: inputs do not cover output plus fee\n"); goto out; }
        change = total_in - send_amt - fee;
    }
    int has_change = (change >= KOINU_DUST);

    if (!kw_tx_add_output(&tx, send_amt, dspk, dl)) { fprintf(stderr, "kw: add output\n"); goto out; }
    if (has_change) {
        uint8_t cspk[25]; size_t cl = 0;
        if (change_arg) {
            if (!addr_to_spk(cp, change_arg, cspk, &cl)) { fprintf(stderr, "kw: bad --change address\n"); goto out; }
        } else {
            kw_bip32_key ck;
            if (!kw_bip44_derive(&master, cp->bip44_coin, 0, 1, 0, &ck)) { fprintf(stderr, "kw: cannot derive change\n"); goto out; }
            uint8_t cpub[33], ch[20];
            kw_bip32_pubkey(&ck, cpub); kw_hash160(cpub, 33, ch);
            h160_to_spk(ch, cspk); cl = 25;
            kw_secure_zero(&ck, sizeof ck);
        }
        if (!kw_tx_add_output(&tx, change, cspk, cl)) { fprintf(stderr, "kw: add change\n"); goto out; }
    }
    /* with no change output, the remainder is left to the miner as fee */

    for (int i = 0; i < nin; i++) {
        if (!kw_tx_sign_p2pkh(&tx, (size_t)i, inkeys[i].key + 1, prevspk[i], 25)) {
            fprintf(stderr, "kw: cannot sign input %d\n", i); goto out;
        }
    }

    {
        uint8_t raw[16384];
        size_t rn = kw_tx_serialize(&tx, raw, sizeof raw);
        if (!rn) { fprintf(stderr, "kw: serialize failed\n"); goto out; }
        char hex[32770];
        kw_hex_encode(raw, rn, hex, sizeof hex);
        uint8_t txid[32], disp[32];
        kw_tx_txid(&tx, txid);
        for (int i = 0; i < 32; i++) disp[i] = txid[31 - i];
        char txidhex[65];
        kw_hex_encode(disp, 32, txidhex, sizeof txidhex);
        printf("txid  %s\n", txidhex);
        printf("raw   %s\n", hex);
        printf("fee   %llu koinu, %zu bytes\n",
               (unsigned long long)(total_in - send_amt - (has_change ? change : 0)), rn);
        rc = 0;
    }
out:
    if (keymap) { kw_secure_zero(keymap, (size_t)keymap_n * sizeof *keymap); free(keymap); }
    free(h160map);
    if (have_us) kw_utxoset_free(&us);
    kw_secure_zero(seed, sizeof seed);
    kw_secure_zero(&master, sizeof master);
    kw_secure_zero(inkeys, sizeof inkeys);
    return rc;
}

/* Sweep an external key: decode its WIF, scan the chain for its one address,
   and spend every output it holds to --to, signed with that key. The key is not
   added to the wallet; only the funds move. Compressed WIF only. */
static int cmd_sweep(const kw_chainparams *cp, const char *wif_arg, const char *to_arg,
                     const char *node, int port, int tor, int use_cf,
                     const char *fee_arg, const char *feerate_arg)
{
    if (!to_arg || !node) { usage(); return 2; }
    if (port <= 0) port = cp->p2p_port;

    char *wif = read_secret(wif_arg, "wif: ");
    if (!wif) { fprintf(stderr, "kw: no wif\n"); return 1; }
    uint8_t pay[64]; size_t plen = 0;
    int okdec = kw_base58check_decode(wif, pay, sizeof pay, &plen);
    secret_free(wif);
    if (!okdec) { fprintf(stderr, "kw: bad wif\n"); return 1; }
    if (pay[0] != cp->wif) { fprintf(stderr, "kw: wif is for another network\n"); kw_secure_zero(pay, sizeof pay); return 1; }
    if (plen == 33) { fprintf(stderr, "kw: uncompressed wif not supported\n"); kw_secure_zero(pay, sizeof pay); return 1; }
    if (plen != 34 || pay[33] != 0x01) { fprintf(stderr, "kw: bad wif\n"); kw_secure_zero(pay, sizeof pay); return 1; }
    uint8_t sk[32]; memcpy(sk, pay + 1, 32); kw_secure_zero(pay, sizeof pay);

    uint8_t pub[33], h[20], spk[25];
    if (!kw_ec_pubkey(sk, pub)) { fprintf(stderr, "kw: bad key\n"); kw_secure_zero(sk, sizeof sk); return 1; }
    kw_hash160(pub, 33, h); h160_to_spk(h, spk);

    uint8_t dspk[25]; size_t dl = 0;
    char tob[160]; snprintf(tob, sizeof tob, "%s", to_arg);
    char *daddr = strtok(tob, ":");
    if (!daddr || !addr_to_spk(cp, daddr, dspk, &dl)) { fprintf(stderr, "kw: bad --to address\n"); kw_secure_zero(sk, sizeof sk); return 1; }

    kw_watchset ws; kw_watchset_init(&ws); kw_watchset_add(&ws, spk, 25);
    kw_net_verbose = 1;
    kw_peer p;
    int conn = tor ? kw_peer_connect_socks5(&p, cp, node, port, 15, "127.0.0.1", 9050)
                   : kw_peer_connect(&p, cp, node, port, 15);
    if (!conn) { fprintf(stderr, "kw: connect to %s:%d failed\n", node, port); kw_watchset_free(&ws); kw_secure_zero(sk, sizeof sk); return 1; }

    int rc = 1;
    kw_utxoset us; int have_us = 0;
    if (!kw_peer_handshake(&p, 0)) { fprintf(stderr, "kw: handshake failed\n"); goto out; }
    {
        kw_headerstore s; kw_headerstore_init(&s);
        long nh = kw_sync_headers(&p, &s, cp);
        if (nh < 0) { fprintf(stderr, "kw: header sync failed\n"); kw_headerstore_free(&s); goto out; }
        kw_utxoset_init(&us); have_us = 1;
        long nb = use_cf ? kw_cf_sync(&p, &s, &us, &ws, 1) : kw_spv_sync_blocks(&p, &s, &us, &ws, 1);
        kw_headerstore_free(&s);
        if (nb < 0) { fprintf(stderr, "kw: %s sync failed\n", use_cf ? "filter" : "block"); goto out; }
    }
    if (kw_utxoset_count(&us) == 0) { fprintf(stderr, "kw: nothing to sweep at that address\n"); goto out; }

    {
        uint64_t rate = KW_MIN_RELAY_FEE_PER_KB;
        if (feerate_arg && !parse_doge(feerate_arg, &rate)) { fprintf(stderr, "kw: bad --feerate\n"); goto out; }
        if (!feerate_arg && p.peer_feerate > (int64_t)rate) rate = (uint64_t)p.peer_feerate;
        int have_fixed = (fee_arg != NULL); uint64_t fixed = 0;
        if (have_fixed && !parse_doge(fee_arg, &fixed)) { fprintf(stderr, "kw: bad --fee\n"); goto out; }

        kw_tx tx; kw_tx_init(&tx);
        uint8_t prevspk[KW_TX_MAX_IN][25];
        int nin = 0; uint64_t total_in = 0;
        for (size_t u = 0; u < us.count && nin < KW_TX_MAX_IN; u++) {
            const kw_utxo *e = &us.u[u];
            if (e->spklen != 25) continue;
            char disphex[65]; uint8_t disp[32];
            for (int b = 0; b < 32; b++) disp[b] = e->txid[31 - b];
            kw_hex_encode(disp, 32, disphex, sizeof disphex);
            if (!kw_tx_add_input(&tx, disphex, e->vout)) break;
            memcpy(prevspk[nin], e->spk, 25);
            total_in += e->value; nin++;
        }
        if ((size_t)nin < us.count) fprintf(stderr, "kw: sweeping %d of %zu utxos (input limit)\n", nin, us.count);

        uint64_t fee = have_fixed ? fixed : est_fee(nin, 1, rate);
        if (total_in <= fee || total_in - fee < KOINU_DUST) { fprintf(stderr, "kw: balance too small to sweep\n"); goto out; }
        uint64_t out_amt = total_in - fee;
        if (!kw_tx_add_output(&tx, out_amt, dspk, dl)) { fprintf(stderr, "kw: add output\n"); goto out; }
        for (int i = 0; i < nin; i++)
            if (!kw_tx_sign_p2pkh(&tx, (size_t)i, sk, prevspk[i], 25)) { fprintf(stderr, "kw: sign failed\n"); goto out; }

        uint8_t raw[16384];
        size_t rn = kw_tx_serialize(&tx, raw, sizeof raw);
        if (!rn) { fprintf(stderr, "kw: serialize failed\n"); goto out; }
        char hex[32770]; kw_hex_encode(raw, rn, hex, sizeof hex);
        uint8_t txid[32], d[32]; kw_tx_txid(&tx, txid);
        for (int i = 0; i < 32; i++) d[i] = txid[31 - i];
        char txidhex[65]; kw_hex_encode(d, 32, txidhex, sizeof txidhex);
        printf("swept %d utxos, %llu koinu to %s\n", nin, (unsigned long long)out_amt, daddr);
        printf("txid  %s\n", txidhex);
        printf("raw   %s\n", hex);
        printf("fee   %llu koinu, %zu bytes\n", (unsigned long long)fee, rn);
        rc = 0;
    }
out:
    if (have_us) kw_utxoset_free(&us);
    kw_peer_close(&p);
    kw_watchset_free(&ws);
    kw_secure_zero(sk, sizeof sk);
    return rc;
}

/* Print the peer's tip height and hash. Header sync only; no keystore. The store
   holds blocks 1..count, so the tip height is the count. */
static int cmd_height(const kw_chainparams *cp, const char *node, int port, int tor,
                      const char *headers_path)
{
    if (!node) { usage(); return 2; }
    if (port <= 0) port = cp->p2p_port;
    kw_net_verbose = 1;
    kw_peer p;
    int conn = tor ? kw_peer_connect_socks5(&p, cp, node, port, 15, "127.0.0.1", 9050)
                   : kw_peer_connect(&p, cp, node, port, 15);
    if (!conn) { fprintf(stderr, "kw: connect to %s:%d failed\n", node, port); return 1; }

    int rc = 1;
    if (!kw_peer_handshake(&p, 0)) { fprintf(stderr, "kw: handshake failed\n"); goto out; }
    {
        kw_headerstore s; headers_open(&s, headers_path);
        long nh = kw_sync_headers(&p, &s, cp);
        if (nh < 0) { fprintf(stderr, "kw: header sync failed\n"); kw_headerstore_free(&s); goto out; }
        if (headers_path) kw_headerstore_save(&s, headers_path);
        const kw_block_header *tip = kw_headerstore_tip(&s);
        char d[65] = "(none)";
        if (tip) { uint8_t r[32]; for (int i = 0; i < 32; i++) r[i] = tip->hash[31 - i]; kw_hex_encode(r, 32, d, sizeof d); }
        printf("height %zu\ntip %s\n", s.count, d);
        kw_headerstore_free(&s);
        rc = 0;
    }
out:
    kw_peer_close(&p);
    return rc;
}

/* Report the confirmation status of an outpoint the caller names, watching the
   script it pays. Exits 0 if the outpoint is unspent (printing depth), 3 if it
   is not in the unspent set (unconfirmed or already spent), 1 on error. Lets a
   caller confirm a funding output to its own depth policy without trusting a
   claimed height. */
static int cmd_outpoint(const kw_chainparams *cp, const char *watch_arg, const char *outpoint_arg,
                        const char *node, int port, int tor, int use_cf,
                        const char *headers_path, const char *filters_path)
{
    if (!watch_arg || !outpoint_arg || !node) { usage(); return 2; }
    if (port <= 0) port = cp->p2p_port;

    uint8_t spk[64]; size_t spklen = 0;
    if (addr_to_spk(cp, watch_arg, spk, &spklen)) { /* an address */ }
    else {
        size_t hl = strlen(watch_arg);
        if (hl < 2 || hl > 128 || hl % 2 || !kw_hex_decode(watch_arg, hl, spk, hl / 2)) {
            fprintf(stderr, "kw: --watch must be an address or scriptPubKey hex\n"); return 1;
        }
        spklen = hl / 2;
    }

    char ob[128]; snprintf(ob, sizeof ob, "%s", outpoint_arg);
    char *ts = strtok(ob, ":"), *vs = strtok(NULL, ":");
    if (!ts || !vs || strlen(ts) != 64) { fprintf(stderr, "kw: --outpoint wants TXID:VOUT\n"); return 1; }
    uint8_t txdisp[32], txint[32];
    if (!kw_hex_decode(ts, 64, txdisp, 32)) { fprintf(stderr, "kw: bad txid\n"); return 1; }
    for (int i = 0; i < 32; i++) txint[i] = txdisp[31 - i];
    uint32_t vout = (uint32_t)strtoul(vs, NULL, 10);

    kw_watchset ws; kw_watchset_init(&ws); kw_watchset_add(&ws, spk, spklen);
    kw_net_verbose = 1;
    kw_peer p;
    int conn = tor ? kw_peer_connect_socks5(&p, cp, node, port, 15, "127.0.0.1", 9050)
                   : kw_peer_connect(&p, cp, node, port, 15);
    if (!conn) { fprintf(stderr, "kw: connect to %s:%d failed\n", node, port); kw_watchset_free(&ws); return 1; }

    int rc = 1;
    kw_utxoset us; int have_us = 0;
    size_t tipheight = 0;
    if (!kw_peer_handshake(&p, 0)) { fprintf(stderr, "kw: handshake failed\n"); goto out; }
    {
        kw_headerstore s; headers_open(&s, headers_path);
        long nh = kw_sync_headers(&p, &s, cp);
        if (nh < 0) { fprintf(stderr, "kw: header sync failed\n"); kw_headerstore_free(&s); goto out; }
        if (headers_path) kw_headerstore_save(&s, headers_path);
        tipheight = s.count;
        kw_utxoset_init(&us); have_us = 1;
        long nb = (use_cf && filters_path) ? kw_cf_scan_cached(&p, &s, &us, &ws, 1, filters_path)
                : use_cf ? kw_cf_sync(&p, &s, &us, &ws, 1) : kw_spv_sync_blocks(&p, &s, &us, &ws, 1);
        kw_headerstore_free(&s);
        if (nb < 0) { fprintf(stderr, "kw: %s sync failed\n", use_cf ? "filter" : "block"); goto out; }
    }
    {
        const kw_utxo *found = NULL;
        for (size_t u = 0; u < us.count; u++)
            if (us.u[u].vout == vout && memcmp(us.u[u].txid, txint, 32) == 0) { found = &us.u[u]; break; }
        if (found) {
            long depth = (long)tipheight - (long)found->height + 1;
            printf("unspent height %u depth %ld value %llu koinu\n",
                   found->height, depth, (unsigned long long)found->value);
            rc = 0;
        } else {
            printf("not found (unconfirmed or already spent)\n");
            rc = 3;
        }
    }
out:
    if (have_us) kw_utxoset_free(&us);
    kw_peer_close(&p);
    kw_watchset_free(&ws);
    return rc;
}

/* Read non-secret text from @FILE, stdin ("-"), or the argument itself. */
static char *read_text(const char *arg)
{
    if (!arg) return NULL;
    if (arg[0] == '@' || !strcmp(arg, "-")) {
        FILE *f = (arg[0] == '@') ? fopen(arg + 1, "r") : stdin;
        if (!f) return NULL;
        char *l = NULL; size_t c = 0; ssize_t n = getline(&l, &c, f);
        if (arg[0] == '@') fclose(f);
        if (n < 0) { free(l); return NULL; }
        chomp(l);
        return l;
    }
    return strdup(arg);
}

/* Broadcast a raw transaction and confirm the peer took it: send the tx, then
   ask for it back by txid. A returned tx means it is in the peer's mempool; a
   notfound or reject means it was refused. */
static int cmd_send(const kw_chainparams *cp, const char *tx_arg, const char *node, int port, int tor)
{
    if (!tx_arg || !node) { usage(); return 2; }
    if (port <= 0) port = cp->p2p_port;

    char *txt = read_text(tx_arg);
    if (!txt) { fprintf(stderr, "kw: cannot read --tx\n"); return 1; }
    size_t hexlen = strlen(txt);
    static uint8_t raw[16384];
    if (hexlen == 0 || hexlen % 2 || hexlen / 2 > sizeof raw || !kw_hex_decode(txt, hexlen, raw, hexlen / 2)) {
        fprintf(stderr, "kw: --tx is not valid hex\n"); free(txt); return 1;
    }
    size_t rawlen = hexlen / 2;
    free(txt);

    uint8_t txid[32], disp[32];
    kw_hash256(raw, rawlen, txid);
    for (int i = 0; i < 32; i++) disp[i] = txid[31 - i];
    char txidhex[65]; kw_hex_encode(disp, 32, txidhex, sizeof txidhex);

    kw_peer p;
    int conn = tor ? kw_peer_connect_socks5(&p, cp, node, port, 15, "127.0.0.1", 9050)
                   : kw_peer_connect(&p, cp, node, port, 10);
    if (!conn) { fprintf(stderr, "kw: connect to %s:%d failed\n", node, port); return 1; }

    int rc = 1;
    if (!kw_peer_handshake(&p, 0)) { fprintf(stderr, "kw: handshake failed\n"); goto out; }
    if (!kw_peer_send(&p, "tx", raw, rawlen)) { fprintf(stderr, "kw: send failed\n"); goto out; }

    /* p2p has no positive accept ack: a node never echoes a tx back to its
       sender. watch for a reject; going quiet means it was relayed. */
    for (;;) {
        char cmd[13]; const uint8_t *pl = NULL; size_t pn = 0;
        int r = kw_peer_recv(&p, cmd, &pl, &pn);
        if (r != 1) { printf("broadcast: %s (no reject; confirm with kw outpoint)\n", txidhex); rc = 0; break; }
        if (!strcmp(cmd, "ping")) { kw_peer_send(&p, "pong", pl, pn); continue; }
        if (!strcmp(cmd, "reject")) {
            char reason[128] = "";
            size_t o = 0;                          /* reject: message, ccode, reason, [data] */
            if (o < pn) { uint8_t ml = pl[o++]; o += ml; }      /* skip the command varstr */
            if (o < pn) o++;                                    /* skip ccode */
            if (o < pn) { uint8_t rl = pl[o++]; if (rl < sizeof reason && o + rl <= pn) { memcpy(reason, pl + o, rl); reason[rl] = 0; } }
            fprintf(stderr, "rejected: %s%s%s\n", txidhex, reason[0] ? " - " : "", reason);
            rc = 1; break;
        }
        /* inv, addr, sendheaders, etc: keep waiting for a possible reject */
    }
out:
    kw_peer_close(&p);
    return rc;
}

int main(int argc, char **argv)
{
    int net = 0, words = 12, change = 0, ninputs = 0;
    int tor = 0, use_cf = 1, gap = 100, port = -1;
    uint32_t account = 0, index = 0;
    const char *path = NULL, *pass_arg = NULL, *mnem_arg = NULL, *cmd = NULL;
    const char *to_arg = NULL, *fee_arg = NULL, *feerate_arg = NULL, *change_arg = NULL;
    const char *node = "127.0.0.1", *utxos_arg = NULL, *wif_arg = NULL;
    const char *watch_arg = NULL, *outpoint_arg = NULL, *headers_arg = NULL, *tx_arg = NULL;
    const char *filters_arg = NULL;
    const char *inputs[KW_TX_MAX_IN];

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        #define NEXT() (++i < argc ? argv[i] : NULL)
        if      (!strcmp(a, "--testnet")) net = 1;
        else if (!strcmp(a, "--regtest")) net = 2;
        else if (!strcmp(a, "--keystore"))   path = NEXT();
        else if (!strcmp(a, "--passphrase")) pass_arg = NEXT();
        else if (!strcmp(a, "--mnemonic"))   mnem_arg = NEXT();
        else if (!strcmp(a, "--words"))    { const char *v = NEXT(); words = v ? atoi(v) : 12; }
        else if (!strcmp(a, "--account"))  { const char *v = NEXT(); account = v ? (uint32_t)strtoul(v,NULL,10) : 0; }
        else if (!strcmp(a, "--index"))    { const char *v = NEXT(); index = v ? (uint32_t)strtoul(v,NULL,10) : 0; }
        else if (!strcmp(a, "--change"))     change = 1;
        else if (!strcmp(a, "--input"))    { const char *v = NEXT(); if (v && ninputs < KW_TX_MAX_IN) inputs[ninputs++] = v; }
        else if (!strcmp(a, "--to"))         to_arg = NEXT();
        else if (!strcmp(a, "--fee"))        fee_arg = NEXT();
        else if (!strcmp(a, "--feerate"))    feerate_arg = NEXT();
        else if (!strcmp(a, "--change-to"))  change_arg = NEXT();
        else if (!strcmp(a, "--node"))       node = NEXT();
        else if (!strcmp(a, "--port"))     { const char *v = NEXT(); port = v ? atoi(v) : -1; }
        else if (!strcmp(a, "--tor"))        tor = 1;
        else if (!strcmp(a, "--spv"))        use_cf = 0;
        else if (!strcmp(a, "--cf"))         use_cf = 1;
        else if (!strcmp(a, "--gap"))      { const char *v = NEXT(); gap = v ? atoi(v) : 100; }
        else if (!strcmp(a, "--utxos"))      utxos_arg = NEXT();
        else if (!strcmp(a, "--wif"))        wif_arg = NEXT();
        else if (!strcmp(a, "--watch"))      watch_arg = NEXT();
        else if (!strcmp(a, "--outpoint"))   outpoint_arg = NEXT();
        else if (!strcmp(a, "--headers"))    headers_arg = NEXT();
        else if (!strcmp(a, "--filters"))    filters_arg = NEXT();
        else if (!strcmp(a, "--tx"))         tx_arg = NEXT();
        else if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(); return 0; }
        else if (a[0] != '-' && !cmd)        cmd = a;
        else { usage(); return 2; }
        #undef NEXT
    }
    if (!cmd) { usage(); return 2; }
    if (gap < 1) gap = 1;

    kw_ec_start();
    const kw_chainparams *cp = chain_for(net);
    int rc;
    if      (!strcmp(cmd, "new"))     rc = cmd_new(cp, path, pass_arg, words);
    else if (!strcmp(cmd, "restore")) rc = cmd_restore(cp, path, pass_arg, mnem_arg);
    else if (!strcmp(cmd, "address")) rc = cmd_address(cp, path, pass_arg, account, (uint32_t)change, index);
    else if (!strcmp(cmd, "scan"))    rc = cmd_scan(cp, path, pass_arg, node, port, tor, use_cf, gap, utxos_arg, headers_arg, filters_arg);
    else if (!strcmp(cmd, "sign"))    rc = cmd_sign(cp, path, pass_arg, (char **)inputs, ninputs, to_arg, fee_arg, feerate_arg, change_arg, utxos_arg, gap);
    else if (!strcmp(cmd, "sweep"))   rc = cmd_sweep(cp, wif_arg, to_arg, node, port, tor, use_cf, fee_arg, feerate_arg);
    else if (!strcmp(cmd, "height"))  rc = cmd_height(cp, node, port, tor, headers_arg);
    else if (!strcmp(cmd, "outpoint")) rc = cmd_outpoint(cp, watch_arg, outpoint_arg, node, port, tor, use_cf, headers_arg, filters_arg);
    else if (!strcmp(cmd, "send"))    rc = cmd_send(cp, tx_arg, node, port, tor);
    else { usage(); rc = 2; }
    kw_ec_stop();
    return rc;
}
