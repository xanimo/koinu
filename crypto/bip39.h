/* dogewallet - BIP39 mnemonics (English)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Entropy <-> mnemonic with the SHA-256 checksum, and mnemonic -> seed via
 * PBKDF2. NFKD normalization is not applied: correct for the English wordlist
 * and ASCII passphrases, which the caller should enforce. */

#ifndef DOGEWALLET_BIP39_H
#define DOGEWALLET_BIP39_H

#include <stddef.h>
#include <stdint.h>

#define DW_BIP39_SEED_LEN 64
/* 24 words * (8-char max + 1 space) is the longest mnemonic; round up. */
#define DW_BIP39_MNEMONIC_MAX 256

/* Entropy (16, 20, 24, 28 or 32 bytes) to a space-joined mnemonic in (out).
   Returns the string length, or 0 on a bad length or too-small buffer. */
size_t dw_bip39_from_entropy(const uint8_t *ent, size_t entlen, char *out, size_t outcap);

/* Draw (entlen) bytes of entropy from the CSPRNG and build a mnemonic. */
size_t dw_bip39_generate(size_t entlen, char *out, size_t outcap);

/* 1 if (mnemonic) is a valid English BIP39 phrase (known words, right length,
   correct checksum). */
int dw_bip39_check(const char *mnemonic);

/* Recover the entropy behind a valid mnemonic. Returns 1 on success with the
   byte length in (outlen), 0 if the mnemonic is invalid or (out) too small. */
int dw_bip39_to_entropy(const char *mnemonic, uint8_t *out, size_t outcap, size_t *outlen);

/* Mnemonic to 64-byte seed: PBKDF2-HMAC-SHA512, salt "mnemonic"+passphrase,
   2048 rounds. Pass "" for no passphrase. Does not validate the checksum, per
   BIP39. Returns 1 on success. */
int dw_bip39_to_seed(const char *mnemonic, const char *passphrase, uint8_t seed[DW_BIP39_SEED_LEN]);

#endif /* DOGEWALLET_BIP39_H */
