/* koinu.dog - merged mining: the proof a Dogecoin block borrows from its parent
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * From height 371337 almost every Dogecoin block is merged-mined, which means its
 * own header does not carry the work. What carries the work is a Litecoin block
 * whose coinbase commits to this block's hash, and the AuxPoW blob between the
 * 80-byte header and the transaction count is that commitment: the parent's
 * coinbase, the branch linking it to the parent's merkle root, the branch linking
 * this chain's slot to the root in that coinbase, and the parent's header.
 *
 * So verifying a merged-mined block is proving four things: the parent's header
 * meets this block's target, the parent's coinbase is in the parent's merkle tree,
 * this block's hash is in the tree the coinbase commits to, and the slot it sits in
 * is the one a nonce and this chain's id determine, which is what stops one proof
 * of work being sold to two chains.
 *
 * The rules are Dogecoin's, from src/auxpow.cpp, and the awkward ones are about the
 * coinbase script rather than the hashing: the merged-mining tag has to sit
 * immediately before the commitment, appear once, and where the tag is absent the
 * commitment has to start early enough that it cannot have been smuggled in after
 * other data. */

#ifndef KOINU_AUXPOW_H
#define KOINU_AUXPOW_H

#include <stddef.h>
#include <stdint.h>

/* 30 is the chain merkle branch limit the rules impose. The coinbase branch is
   bounded by how deep a real block's merkle tree can be, and 32 is past any
   block that could exist. */
#define KW_AUXPOW_MAX_CHAIN  30
#define KW_AUXPOW_MAX_MERKLE 32

/* Dogecoin's merged-mining chain id, which the parent must not share. */
#define KW_AUXPOW_CHAIN_ID 0x0062

typedef struct {
    const uint8_t *coinbase;    /* the parent's coinbase transaction, as serialised */
    size_t         coinbase_len;

    /* The same transaction with the witness taken out, which is what its txid is
       hashed over and so what the parent's merkle tree holds. A segwit coinbase
       serialises as version, marker, flag, vin, vout, witness, locktime, and the
       txid covers version, vin, vout and locktime only. Held as the runs of bytes
       that make that up, so hashing it copies nothing: one run without a witness,
       three with. */
    struct { const uint8_t *p; size_t len; } strip[3];
    int nstrip;
    const uint8_t *script;      /* its first input's scriptSig, where the tag lives */
    size_t         script_len;

    uint8_t  merkle[KW_AUXPOW_MAX_MERKLE][32];   /* coinbase to parent merkle root */
    size_t   nmerkle;
    int32_t  index;                              /* must be 0: a coinbase is first */

    uint8_t  chain[KW_AUXPOW_MAX_CHAIN][32];     /* our hash to the committed root */
    size_t   nchain;
    int32_t  chain_index;

    const uint8_t *parent;      /* the parent block's 80-byte header */
} kw_auxpow;

/* Parse the blob at (in + *off), advancing *off past it. (ap) may be NULL to step
   over it without recording, which is what a sync that is not verifying wants.
   Returns 1, or 0 if the blob is malformed or a branch is longer than the limits
   above. Pointers in (ap) borrow from (in) and are valid while it is. */
int kw_auxpow_parse(const uint8_t *in, size_t len, size_t *off, kw_auxpow *ap);

/* Check the proof against the block it belongs to. (aux_hash) is sha256d of that
   block's 80-byte header in internal order and (aux_bits) its nBits, so the work
   is measured against the target the Dogecoin chain demanded. (scratch) is
   KW_SCRYPT_SCRATCH bytes or NULL. Returns 1 when every rule holds. */
int kw_auxpow_check(const kw_auxpow *ap, const uint8_t aux_hash[32], uint32_t aux_bits,
                    int32_t chain_id, void *scratch);

/* Every rule except the parent's work. A validator hashing eight parents at once
   needs the structure checked separately from the hashing, since the batch core
   wants all eight headers together; ap->parent is the 80 bytes it must hash. */
int kw_auxpow_check_structure(const kw_auxpow *ap, const uint8_t aux_hash[32],
                              int32_t chain_id);

/* The slot a nonce and a chain id put this chain in, for a tree of height (h).
   Exposed because it is the one rule with no data to check it against: a test has
   to recompute it the same way. */
uint32_t kw_auxpow_expected_index(uint32_t nonce, int32_t chain_id, unsigned h);

#endif /* KOINU_AUXPOW_H */
