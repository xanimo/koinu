/* dogewallet - BIP32 hierarchical deterministic keys
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#ifndef DOGEWALLET_BIP32_H
#define DOGEWALLET_BIP32_H

#include <stddef.h>
#include <stdint.h>

#define DW_BIP32_SERIALIZED_LEN 78
#define DW_BIP32_HARDENED 0x80000000u

/* Network version bytes for the extended-key serialization: the prv/pub pair a
   coin uses (Bitcoin mainnet is 0x0488ade4 / 0x0488b21e). Kept out of the core
   so derivation is network-agnostic and the BIP32 vectors can be reproduced. */
typedef struct { uint32_t prv, pub; } dw_bip32_version;

typedef struct {
    uint8_t  is_private;        /* 1: key holds a secret; 0: public only     */
    uint8_t  depth;
    uint8_t  parent_fp[4];      /* first 4 bytes of hash160(parent pubkey)    */
    uint32_t child_number;
    uint8_t  chain_code[32];
    uint8_t  key[33];           /* private: 0x00 || d ; public: compressed P  */
    dw_bip32_version ver;
} dw_bip32_key;

/* Master key from a seed: I = HMAC-SHA512("Bitcoin seed", seed). Returns 1, or
   0 if the seed yields an invalid master secret (retry with another seed). */
int  dw_bip32_from_seed(const uint8_t *seed, size_t seedlen,
                        dw_bip32_version ver, dw_bip32_key *out);

/* The compressed public key for (k), whether it holds a secret or not. */
void dw_bip32_pubkey(const dw_bip32_key *k, uint8_t pub[33]);

/* Child derivation. CKDpriv needs a private parent; CKDpub cannot do a hardened
   index. Both return 0 when the index is unusable (tweak out of range), which
   BIP32 says to treat as "skip to the next index". */
int  dw_bip32_ckd_priv(const dw_bip32_key *parent, uint32_t index, dw_bip32_key *out);
int  dw_bip32_ckd_pub(const dw_bip32_key *parent, uint32_t index, dw_bip32_key *out);

/* Strip the secret, leaving the matching extended public key. */
void dw_bip32_neuter(const dw_bip32_key *prv, dw_bip32_key *pub);

/* xprv/xpub base58check. serialize returns the string length or 0; parse
   returns 1 on success and sets only the version half matching the key type. */
size_t dw_bip32_serialize(const dw_bip32_key *k, char *out, size_t outcap);
int    dw_bip32_parse(const char *str, dw_bip32_key *out);

/* Derive along a path like "m/44'/3'/0'/0/0" ("'" or "h" marks hardened). A
   public master can only walk non-hardened steps. Returns 1 on success. */
int  dw_bip32_derive_path(const dw_bip32_key *master, const char *path, dw_bip32_key *out);

#endif /* DOGEWALLET_BIP32_H */
