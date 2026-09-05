/* kw - a thin cli over libdogewallet
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
#include "tx.h"
#include "hex.h"
#include "ec.h"
#include "mem.h"

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
      "  sign     --keystore PATH [--passphrase @FILE|-] --fee DOGE\n"
      "           --input TXID:VOUT:AMOUNT:INDEX ...  --to ADDR:AMOUNT\n"
      "           [--change-to ADDR]\n"
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

static const dw_chainparams *chain_for(int net) /* 0 main, 1 test, 2 regtest */
{
    if (net == 1) return &DW_DOGE_TESTNET;
    if (net == 2) return &DW_DOGE_REGTEST;
    return &DW_DOGE_MAINNET;
}

/* Derive the seed's first-account key at (change,index) into an address. */
static int derive_address(const dw_chainparams *cp, const uint8_t seed[64],
                          uint32_t account, uint32_t change, uint32_t index,
                          char *addr, size_t addrcap)
{
    dw_bip32_key master, key;
    if (!dw_bip32_from_seed(seed, 64, cp->bip32, &master)) return 0;
    int ok = dw_bip44_derive(&master, cp->bip44_coin, account, change, index, &key);
    if (ok) {
        uint8_t pub[33], h160[20];
        dw_bip32_pubkey(&key, pub);
        dw_hash160(pub, 33, h160);
        ok = dw_address_p2pkh(pub, cp->p2pkh, addr, addrcap) != 0;
    }
    dw_secure_zero(&master, sizeof master);
    dw_secure_zero(&key, sizeof key);
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

/* an address to its scriptPubKey, p2pkh or p2sh, for this network */
static int addr_to_spk(const dw_chainparams *cp, const char *addr, uint8_t *out, size_t *len)
{
    uint8_t pay[64]; size_t n = 0;
    if (!dw_base58check_decode(addr, pay, sizeof pay, &n) || n != 21) return 0;
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

/* seal a seed under a passphrase and write it, then print the first address */
static int seal_and_report(const dw_chainparams *cp, const char *path,
                           const char *pass_arg, const uint8_t seed[64])
{
    char *pass = read_secret(pass_arg, "new passphrase: ");
    if (!pass) { fprintf(stderr, "kw: no passphrase\n"); return 1; }

    uint8_t blob[8192];
    size_t n = dw_keystore_seal(seed, 64, pass, &DW_KEYSTORE_DEFAULT, blob, sizeof blob);
    secret_free(pass);
    if (!n) { fprintf(stderr, "kw: seal failed\n"); return 1; }
    if (!write_new_keystore(path, blob, n)) { dw_secure_zero(blob, sizeof blob); return 1; }
    dw_secure_zero(blob, sizeof blob);

    char addr[128];
    if (derive_address(cp, seed, 0, 0, 0, addr, sizeof addr))
        printf("first address  %s\n", addr);
    printf("keystore       %s\n", path);
    return 0;
}

static int cmd_new(const dw_chainparams *cp, const char *path, const char *pass_arg, int words)
{
    if (!path) { usage(); return 2; }
    size_t entlen = (words == 24) ? 32 : 16;

    char mnem[DW_BIP39_MNEMONIC_MAX];
    if (!dw_bip39_generate(entlen, mnem, sizeof mnem)) { fprintf(stderr, "kw: generate failed\n"); return 1; }

    uint8_t seed[64];
    dw_bip39_to_seed(mnem, "", seed);

    printf("mnemonic (write this down, it is your only backup):\n  %s\n\n", mnem);
    dw_secure_zero(mnem, sizeof mnem);

    int rc = seal_and_report(cp, path, pass_arg, seed);
    dw_secure_zero(seed, sizeof seed);
    return rc;
}

static int cmd_restore(const dw_chainparams *cp, const char *path,
                       const char *pass_arg, const char *mnem_arg)
{
    if (!path) { usage(); return 2; }
    char *mnem = read_secret(mnem_arg, "mnemonic: ");
    if (!mnem) { fprintf(stderr, "kw: no mnemonic\n"); return 1; }
    if (!dw_bip39_check(mnem)) { secret_free(mnem); fprintf(stderr, "kw: invalid mnemonic\n"); return 1; }

    uint8_t seed[64];
    dw_bip39_to_seed(mnem, "", seed);
    secret_free(mnem);

    int rc = seal_and_report(cp, path, pass_arg, seed);
    dw_secure_zero(seed, sizeof seed);
    return rc;
}

static int cmd_address(const dw_chainparams *cp, const char *path, const char *pass_arg,
                       uint32_t account, uint32_t change, uint32_t index)
{
    if (!path) { usage(); return 2; }
    uint8_t blob[8192]; size_t n = 0;
    if (!read_keystore(path, blob, sizeof blob, &n)) return 1;

    char *pass = read_secret(pass_arg, "passphrase: ");
    if (!pass) { fprintf(stderr, "kw: no passphrase\n"); return 1; }

    uint8_t seed[64]; size_t slen = 0;
    int opened = dw_keystore_open(blob, n, pass, seed, sizeof seed, &slen);
    secret_free(pass);
    dw_secure_zero(blob, sizeof blob);
    if (!opened || slen != 64) { fprintf(stderr, "kw: wrong passphrase or corrupt keystore\n"); return 1; }

    char addr[128];
    int ok = derive_address(cp, seed, account, change, index, addr, sizeof addr);
    dw_secure_zero(seed, sizeof seed);
    if (!ok) { fprintf(stderr, "kw: derivation failed\n"); return 1; }
    printf("%s\n", addr);
    return 0;
}

/* Offline signer: the operator supplies the outpoints to spend (a chain source
   will supply them automatically once the light client tracks the utxo set).
   Each input is owned by our key at m/44'/coin'/0'/0/INDEX. */
static int cmd_sign(const dw_chainparams *cp, const char *path, const char *pass_arg,
                    char **inputs, int ninputs, const char *to_arg,
                    const char *fee_arg, const char *change_arg)
{
    if (!path || ninputs <= 0 || !to_arg || !fee_arg) { usage(); return 2; }

    uint8_t blob[8192]; size_t bn = 0;
    if (!read_keystore(path, blob, sizeof blob, &bn)) return 1;
    char *pass = read_secret(pass_arg, "passphrase: ");
    if (!pass) return 1;
    uint8_t seed[64]; size_t slen = 0;
    int opened = dw_keystore_open(blob, bn, pass, seed, sizeof seed, &slen);
    secret_free(pass);
    dw_secure_zero(blob, sizeof blob);
    if (!opened || slen != 64) { fprintf(stderr, "kw: wrong passphrase or corrupt keystore\n"); return 1; }

    dw_bip32_key master, inkeys[DW_TX_MAX_IN];
    int rc = 1;
    if (!dw_bip32_from_seed(seed, 64, cp->bip32, &master)) { dw_secure_zero(seed, sizeof seed); return 1; }

    dw_tx tx;
    dw_tx_init(&tx);
    uint8_t prevspk[DW_TX_MAX_IN][25];
    uint64_t total_in = 0;

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
        if (!dw_bip44_derive(&master, cp->bip44_coin, 0, 0, index, &inkeys[i])) {
            fprintf(stderr, "kw: cannot derive input %d\n", i); goto out;
        }
        uint8_t pub[33], h[20];
        dw_bip32_pubkey(&inkeys[i], pub);
        dw_hash160(pub, 33, h);
        prevspk[i][0]=0x76; prevspk[i][1]=0xa9; prevspk[i][2]=0x14;
        memcpy(prevspk[i]+3, h, 20); prevspk[i][23]=0x88; prevspk[i][24]=0xac;
        if (!dw_tx_add_input(&tx, txid, vout)) { fprintf(stderr, "kw: too many inputs\n"); goto out; }
        total_in += amt;
    }

    {
        char tob[160];
        snprintf(tob, sizeof tob, "%s", to_arg);
        char *daddr = strtok(tob, ":"), *dam = strtok(NULL, ":");
        uint64_t send_amt;
        if (!daddr || !dam || !parse_doge(dam, &send_amt)) { fprintf(stderr, "kw: bad --to, want ADDR:AMOUNT\n"); goto out; }
        uint8_t dspk[25]; size_t dl = 0;
        if (!addr_to_spk(cp, daddr, dspk, &dl)) { fprintf(stderr, "kw: bad --to address\n"); goto out; }
        if (!dw_tx_add_output(&tx, send_amt, dspk, dl)) { fprintf(stderr, "kw: add output\n"); goto out; }

        uint64_t fee;
        if (!parse_doge(fee_arg, &fee)) { fprintf(stderr, "kw: bad --fee\n"); goto out; }
        if (total_in < send_amt + fee) { fprintf(stderr, "kw: inputs do not cover output plus fee\n"); goto out; }
        uint64_t change = total_in - send_amt - fee;
        if (change >= KOINU_DUST) {
            uint8_t cspk[25]; size_t cl = 0;
            if (change_arg) {
                if (!addr_to_spk(cp, change_arg, cspk, &cl)) { fprintf(stderr, "kw: bad --change address\n"); goto out; }
            } else {
                dw_bip32_key ck;
                if (!dw_bip44_derive(&master, cp->bip44_coin, 0, 1, 0, &ck)) { fprintf(stderr, "kw: cannot derive change\n"); goto out; }
                uint8_t cpub[33], ch[20];
                dw_bip32_pubkey(&ck, cpub); dw_hash160(cpub, 33, ch);
                cspk[0]=0x76; cspk[1]=0xa9; cspk[2]=0x14; memcpy(cspk+3, ch, 20); cspk[23]=0x88; cspk[24]=0xac; cl = 25;
                dw_secure_zero(&ck, sizeof ck);
            }
            if (!dw_tx_add_output(&tx, change, cspk, cl)) { fprintf(stderr, "kw: add change\n"); goto out; }
        }
        /* change below the dust threshold is left to the miner as extra fee */
    }

    for (int i = 0; i < ninputs; i++) {
        if (!dw_tx_sign_p2pkh(&tx, (size_t)i, inkeys[i].key + 1, prevspk[i], 25)) {
            fprintf(stderr, "kw: cannot sign input %d\n", i); goto out;
        }
    }

    {
        uint8_t raw[16384];
        size_t rn = dw_tx_serialize(&tx, raw, sizeof raw);
        if (!rn) { fprintf(stderr, "kw: serialize failed\n"); goto out; }
        char hex[32770];
        dw_hex_encode(raw, rn, hex, sizeof hex);
        uint8_t txid[32], disp[32];
        dw_tx_txid(&tx, txid);
        for (int i = 0; i < 32; i++) disp[i] = txid[31 - i];
        char txidhex[65];
        dw_hex_encode(disp, 32, txidhex, sizeof txidhex);
        printf("txid  %s\n", txidhex);
        printf("raw   %s\n", hex);
        rc = 0;
    }
out:
    dw_secure_zero(seed, sizeof seed);
    dw_secure_zero(&master, sizeof master);
    dw_secure_zero(inkeys, sizeof inkeys);
    return rc;
}

int main(int argc, char **argv)
{
    int net = 0, words = 12, change = 0, ninputs = 0;
    uint32_t account = 0, index = 0;
    const char *path = NULL, *pass_arg = NULL, *mnem_arg = NULL, *cmd = NULL;
    const char *to_arg = NULL, *fee_arg = NULL, *change_arg = NULL;
    const char *inputs[DW_TX_MAX_IN];

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
        else if (!strcmp(a, "--input"))    { const char *v = NEXT(); if (v && ninputs < DW_TX_MAX_IN) inputs[ninputs++] = v; }
        else if (!strcmp(a, "--to"))         to_arg = NEXT();
        else if (!strcmp(a, "--fee"))        fee_arg = NEXT();
        else if (!strcmp(a, "--change-to"))  change_arg = NEXT();
        else if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(); return 0; }
        else if (a[0] != '-' && !cmd)        cmd = a;
        else { usage(); return 2; }
        #undef NEXT
    }
    if (!cmd) { usage(); return 2; }

    dw_ec_start();
    const dw_chainparams *cp = chain_for(net);
    int rc;
    if      (!strcmp(cmd, "new"))     rc = cmd_new(cp, path, pass_arg, words);
    else if (!strcmp(cmd, "restore")) rc = cmd_restore(cp, path, pass_arg, mnem_arg);
    else if (!strcmp(cmd, "address")) rc = cmd_address(cp, path, pass_arg, account, (uint32_t)change, index);
    else if (!strcmp(cmd, "sign"))    rc = cmd_sign(cp, path, pass_arg, (char **)inputs, ninputs, to_arg, fee_arg, change_arg);
    else { usage(); rc = 2; }
    dw_ec_stop();
    return rc;
}
