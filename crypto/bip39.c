/* koinu.dog - BIP39 mnemonics (English)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "bip39.h"
#include "sha2.h"
#include "pbkdf2.h"
#include "rng.h"
#include "mem.h"
#include "wordlist_en.h"

#include <stdlib.h>
#include <string.h>

/* big-endian bit access over a byte buffer */
static uint32_t get_bits(const uint8_t *buf, size_t bitpos, int n)
{
    uint32_t v = 0;
    for (int i = 0; i < n; i++) {
        size_t b = bitpos + (size_t)i;
        v = (v << 1) | ((buf[b / 8] >> (7 - (b % 8))) & 1u);
    }
    return v;
}
static void put_bits(uint8_t *buf, size_t bitpos, int n, uint32_t v)
{
    for (int i = 0; i < n; i++) {
        if ((v >> (n - 1 - i)) & 1u) {
            size_t b = bitpos + (size_t)i;
            buf[b / 8] |= (uint8_t)(1u << (7 - (b % 8)));
        }
    }
}

/* the wordlist is sorted, so a word's index is a binary search */
static int word_index(const char *w, size_t len)
{
    int lo = 0, hi = 2047;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        const char *m = KW_BIP39_WORDLIST_EN[mid];
        int c = strncmp(w, m, len);
        if (c == 0 && m[len] != '\0') c = -1;   /* w is a prefix of m */
        if (c == 0) return mid;
        if (c < 0) hi = mid - 1; else lo = mid + 1;
    }
    return -1;
}

static int valid_entlen(size_t n) { return n==16||n==20||n==24||n==28||n==32; }

size_t kw_bip39_from_entropy(const uint8_t *ent, size_t entlen, char *out, size_t outcap)
{
    if (!valid_entlen(entlen)) return 0;
    int cs_bits = (int)(entlen / 4);          /* ENT/32 */
    size_t words = (entlen * 8 + cs_bits) / 11;

    uint8_t buf[33];
    memcpy(buf, ent, entlen);
    uint8_t h[KW_SHA256_LEN];
    kw_sha256(ent, entlen, h);
    buf[entlen] = h[0];                        /* only the top cs_bits are read */

    size_t k = 0;
    for (size_t i = 0; i < words; i++) {
        uint32_t idx = get_bits(buf, i * 11, 11);
        const char *w = KW_BIP39_WORDLIST_EN[idx];
        size_t wl = strlen(w);
        if (k + wl + (i ? 1 : 0) + 1 > outcap) { kw_secure_zero(buf, sizeof buf); return 0; }
        if (i) out[k++] = ' ';
        memcpy(out + k, w, wl); k += wl;
    }
    out[k] = '\0';
    kw_secure_zero(buf, sizeof buf);
    kw_secure_zero(h, sizeof h);
    return k;
}

size_t kw_bip39_generate(size_t entlen, char *out, size_t outcap)
{
    if (!valid_entlen(entlen)) return 0;
    uint8_t ent[32];
    if (!kw_random_bytes(ent, entlen)) return 0;
    size_t n = kw_bip39_from_entropy(ent, entlen, out, outcap);
    kw_secure_zero(ent, sizeof ent);
    return n;
}

/* Parse a mnemonic into word indices. Returns the word count, or 0 on an
   unusable phrase (bad count, unknown word, stray formatting). */
static size_t parse_words(const char *m, uint16_t idx[24])
{
    size_t count = 0;
    const char *p = m;
    while (*p == ' ') p++;
    while (*p) {
        const char *start = p;
        while (*p && *p != ' ') p++;
        size_t len = (size_t)(p - start);
        if (count >= 24 || len == 0) return 0;
        int wi = word_index(start, len);
        if (wi < 0) return 0;
        idx[count++] = (uint16_t)wi;
        while (*p == ' ') p++;
    }
    if (!(count==12||count==15||count==18||count==21||count==24)) return 0;
    return count;
}

/* Shared core for check and to_entropy: rebuild entropy, verify the checksum.
   On success writes entropy to (ent_out) if non-NULL and sets *entlen_out. */
static int decode(const char *mnemonic, uint8_t *ent_out, size_t entcap, size_t *entlen_out)
{
    uint16_t idx[24];
    size_t words = parse_words(mnemonic, idx);
    if (!words) return 0;

    size_t total_bits = words * 11;
    int cs_bits = (int)(total_bits / 33);
    size_t ent_bits = total_bits - (size_t)cs_bits;
    size_t entlen = ent_bits / 8;

    uint8_t buf[34];
    memset(buf, 0, sizeof buf);
    for (size_t i = 0; i < words; i++) put_bits(buf, i * 11, 11, idx[i]);

    uint8_t h[KW_SHA256_LEN];
    kw_sha256(buf, entlen, h);
    uint32_t want = get_bits(h, 0, cs_bits);
    uint32_t got  = get_bits(buf, ent_bits, cs_bits);
    int ok = (want == got);

    if (ok && ent_out) {
        if (entlen > entcap) ok = 0;
        else memcpy(ent_out, buf, entlen);
    }
    if (ok && entlen_out) *entlen_out = entlen;

    kw_secure_zero(buf, sizeof buf);
    kw_secure_zero(h, sizeof h);
    return ok;
}

int kw_bip39_check(const char *mnemonic)
{
    return decode(mnemonic, NULL, 0, NULL);
}

int kw_bip39_to_entropy(const char *mnemonic, uint8_t *out, size_t outcap, size_t *outlen)
{
    return decode(mnemonic, out, outcap, outlen);
}

int kw_bip39_to_seed(const char *mnemonic, const char *passphrase, uint8_t seed[KW_BIP39_SEED_LEN])
{
    if (!passphrase) passphrase = "";
    size_t plen = strlen(passphrase);
    size_t saltlen = 8 + plen;                 /* "mnemonic" + passphrase */
    uint8_t *salt = (uint8_t *)malloc(saltlen);
    if (!salt) return 0;
    memcpy(salt, "mnemonic", 8);
    memcpy(salt + 8, passphrase, plen);

    int ok = kw_pbkdf2_hmac_sha512((const uint8_t *)mnemonic, strlen(mnemonic),
                                   salt, saltlen, 2048, seed, KW_BIP39_SEED_LEN);
    kw_secure_zero(salt, saltlen);
    free(salt);
    return ok;
}
