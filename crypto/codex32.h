/* koinu.dog - codex32 (BIP-93) shares of the BIP32 master seed
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * The other way to split the seed. Where SLIP-39 is words and a machine,
 * codex32 is base32 and a pen: the checksum is a BCH code over GF(32) that a
 * person can verify by hand from a printed table, and the Shamir arithmetic is
 * over the same field, so a share can be recomputed with no computer in the
 * room. What that buys is a backup whose integrity does not rest on trusting
 * the machine that reads it back.
 *
 * What it costs against SLIP-39: no passphrase, no digest over the
 * reconstructed secret, and one flat threshold rather than groups. A wrong set
 * of valid shares reconstructs a wrong seed silently, so the check is the
 * fingerprint at the end rather than anything in the format.
 *
 * koinu's seed is 64 bytes, which is the long codex32 form: 127 characters per
 * share, 103 of them payload. */

#ifndef KOINU_CODEX32_H
#define KOINU_CODEX32_H

#include <stddef.h>
#include <stdint.h>

/* 127 characters and a NUL, the longest BIP-93 allows for a master seed. */
#define KW_CODEX32_MAX_LEN     128
/* The data part without its checksum: a 6-character header and 103 payload. */
#define KW_CODEX32_MAX_SYM     109
/* Share indices are bech32 letters in alphabetical order, "s" reserved for the
   secret, so a, c, d, e, f, g, h, j, k, l, m, n, p, q, r, t, u, v, w, x, y, z. */
#define KW_CODEX32_MAX_SHARES  22
#define KW_CODEX32_MAX_SECRET  64
/* The share index that denotes the unshared secret. */
#define KW_CODEX32_SECRET      16

typedef enum {
    KW_CODEX32_OK = 0,
    KW_CODEX32_ARG,        /* a parameter is out of range */
    KW_CODEX32_CHARSET,    /* a character is not bech32, or the case is mixed */
    KW_CODEX32_LENGTH,     /* not one of the six lengths BIP-93 allows */
    KW_CODEX32_PREFIX,     /* missing "ms1", or a threshold that is not a digit */
    KW_CODEX32_CHECKSUM,
    KW_CODEX32_GROUPING,   /* shares disagree, or the wrong set was given */
    KW_CODEX32_RNG
} kw_codex32_err;

const char *kw_codex32_strerror(kw_codex32_err e);

/* A decoded string as its data part in 5-bit symbols, checksum stripped.
   Symbol 0 is the threshold, 1 to 4 the identifier, 5 the share index, and the
   rest the payload. Kept as symbols rather than bytes because interpolation is
   per symbol and a GF(32) multiply mixes all five bits of one: the payload's
   trailing pad bits reach the secret's last byte, so a share truncated to bytes
   reconstructs the wrong seed. */
typedef struct {
    uint8_t sym[KW_CODEX32_MAX_SYM];
    size_t  nsym;
} kw_codex32;

kw_codex32_err kw_codex32_decode(const char *s, kw_codex32 *out);
kw_codex32_err kw_codex32_encode(const kw_codex32 *c, char *out, size_t outcap);

/* 0 for an unshared secret, 2 to 9 for a share, 0xff when the symbol is not a
   digit at all, which only a hand-built struct can be. */
uint8_t kw_codex32_threshold(const kw_codex32 *c);
/* 0 to 31; KW_CODEX32_SECRET means the string is the secret, not a share. */
uint8_t kw_codex32_index(const kw_codex32 *c);
/* The 4-character identifier, NUL terminated. */
void    kw_codex32_id(const kw_codex32 *c, char out[5]);

/* The payload as seed bytes. The trailing partial group is discarded, which
   BIP-93 does not require to be zero. */
kw_codex32_err kw_codex32_seed(const kw_codex32 *c, uint8_t *out, size_t outcap,
                               size_t *outlen);

/* Build the secret string (share index "s") for (seed) under (threshold) and
   (id), which is 4 bech32 characters. The pad bits are zero. */
kw_codex32_err kw_codex32_from_seed(uint8_t threshold, const char *id,
                                    const uint8_t *seed, size_t seedlen,
                                    kw_codex32 *out);

/* Split (seed) into (count) shares needing (threshold) of them, written to
   out + i * stride for i in [0, count). stride must be at least
   KW_CODEX32_MAX_LEN. (id) is 4 bech32 characters, or NULL for a random one.
   threshold is 2 to 9, since BIP-93 has no 1, and count is at most
   KW_CODEX32_MAX_SHARES. None of the shares is the secret. */
kw_codex32_err kw_codex32_split(const uint8_t *seed, size_t seedlen,
                                const char *id, uint8_t threshold, uint8_t count,
                                char *out, size_t stride, size_t *nout);

/* Reconstruct the seed from exactly (n) shares where n is their common
   threshold. More or fewer is refused rather than worked with.

   Nothing here checks that the result is the seed that was split. The checksum
   catches a mistyped share and the format catches a share from another set, and
   a set of valid shares from one set still reconstructs whatever polynomial
   they describe. Compare the fingerprint. */
kw_codex32_err kw_codex32_combine(const char *const *shares, size_t n,
                                  uint8_t *out, size_t outcap, size_t *outlen);

/* One more share at (index) from exactly a threshold of existing strings, which
   is how a lost share is replaced without reconstituting the seed anywhere. */
kw_codex32_err kw_codex32_derive(const char *const *shares, size_t n,
                                 uint8_t index, char *out, size_t outcap);

#endif /* KOINU_CODEX32_H */
