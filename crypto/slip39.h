/* koinu.dog - SLIP-39 Shamir backup of the BIP32 master seed
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Splits a secret into mnemonic shares, any threshold of which reconstructs it
 * and any fewer of which reveal nothing. Two levels: a group threshold over
 * groups, and a member threshold within each group.
 *
 * The secret split here is koinu's 64-byte BIP32 master seed, which is what
 * SLIP-39 names as the master secret to use, so a set of shares restores the
 * same wallet the mnemonic does and restores it in any SLIP-39 implementation.
 * A 512-bit secret yields 59-word shares, and Trezor's firmware accepts only
 * the 20- and 33-word shares a 128- or 256-bit secret gives, so these shares
 * combine in software and not on that device.
 *
 * NFKD normalization is not applied to the passphrase. The spec requires
 * printable ASCII and this refuses anything else, which makes the two the
 * same thing. */

#ifndef KOINU_SLIP39_H
#define KOINU_SLIP39_H

#include <stddef.h>
#include <stdint.h>

#define KW_SLIP39_MIN_SECRET   16
#define KW_SLIP39_MAX_SECRET   64
#define KW_SLIP39_MAX_SHARES   16
#define KW_SLIP39_MAX_GROUPS   16
#define KW_SLIP39_MAX_TOTAL    (KW_SLIP39_MAX_GROUPS * KW_SLIP39_MAX_SHARES)
#define KW_SLIP39_PASS_MAX     256

/* 20 words for a 128-bit secret, 59 for a 512-bit one. */
#define KW_SLIP39_MIN_WORDS    20
#define KW_SLIP39_MAX_WORDS    59
/* Longest word is 8 characters, so 59 of them separated by spaces. */
#define KW_SLIP39_MNEMONIC_MAX 544

typedef enum {
    KW_SLIP39_OK = 0,
    KW_SLIP39_ARG,        /* a parameter is out of range */
    KW_SLIP39_WORD,       /* a word is not in the list */
    KW_SLIP39_LENGTH,     /* wrong number of words, or a share too short */
    KW_SLIP39_CHECKSUM,   /* RS1024 refused the share */
    KW_SLIP39_PADDING,    /* padding is too long, or not zero */
    KW_SLIP39_GROUPING,   /* shares disagree, or the wrong set was given */
    KW_SLIP39_DIGEST,     /* reconstructed a secret its own digest refuses */
    KW_SLIP39_RNG
} kw_slip39_err;

const char *kw_slip39_strerror(kw_slip39_err e);

/* One share, as the mnemonic encodes it. Thresholds and counts are the actual
   values, not the off-by-one the wire format stores. */
typedef struct {
    uint16_t id;                /* 15 bits, the same across one backup */
    uint8_t  ext;               /* extendable: id is not a salt when 1 */
    uint8_t  e;                 /* iteration exponent */
    uint8_t  group_index;
    uint8_t  group_threshold;
    uint8_t  group_count;
    uint8_t  member_index;
    uint8_t  member_threshold;
    size_t   valuelen;
    uint8_t  value[KW_SLIP39_MAX_SECRET];
} kw_slip39_share;

/* Mnemonic to share and back. Decoding checks the words, the checksum and the
   padding, and nothing about whether the share belongs to a usable set: that
   is a property of a set, and kw_slip39_combine checks it. */
kw_slip39_err kw_slip39_decode(const char *mnemonic, kw_slip39_share *out);
kw_slip39_err kw_slip39_encode(const kw_slip39_share *s, char *out, size_t outcap);

typedef struct {
    uint8_t threshold;          /* shares of this group needed */
    uint8_t count;              /* shares of this group produced */
} kw_slip39_group;

/* Split (ms) into one mnemonic per member share of every group, written to
   out + i * stride for i in [0, *nout). stride must be at least
   KW_SLIP39_MNEMONIC_MAX, and (out) must hold one stride per share across every
   group, which is the sum of the group counts. (e) is the iteration exponent:
   PBKDF2 runs 10000 << e rounds in total, so 0 is the spec's baseline.

   A threshold of 1 with a count above 1 is refused at either level, since the
   shares would be identical copies and the threshold a lie about them. */
kw_slip39_err kw_slip39_split(const uint8_t *ms, size_t mslen,
                              const char *passphrase, uint8_t e,
                              uint8_t group_threshold,
                              const kw_slip39_group *groups, size_t ngroups,
                              char *out, size_t stride, size_t *nout);

/* Reconstruct the secret from exactly the shares a threshold needs: as many
   groups as the group threshold, and within each of those as many members as
   that group's member threshold. More than that is refused rather than
   ignored, so a set that does not say what it reconstructs cannot be given.

   There is no way to tell a wrong passphrase from a right one. Every
   passphrase yields a secret, and a wrong one yields a different wallet. */
kw_slip39_err kw_slip39_combine(const char *const *mnemonics, size_t n,
                                const char *passphrase,
                                uint8_t *out, size_t outcap, size_t *outlen);

#endif /* KOINU_SLIP39_H */
