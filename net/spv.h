/* koinu.dog - classic SPV: full-block download and local scan
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * The default backend on today's protocol. It asks for whole blocks and scans
 * every transaction locally against the watch set, so the peer never learns
 * which outputs are ours (unlike a BIP37 bloom filter). Higher bandwidth than
 * compact filters, which is the later BIP157/158 path. */

#ifndef KOINU_SPV_H
#define KOINU_SPV_H

#include <stddef.h>
#include <stdint.h>

#include "peer.h"
#include "headers.h"
#include "utxo.h"

#define KW_INV_MSG_BLOCK 2

/* Build a getdata requesting full blocks: an inv count, then a (type, hash) each
   with type MSG_BLOCK. Hashes are internal byte order. Returns length or 0. */
size_t kw_msg_getdata_blocks_build(const uint8_t (*hashes)[32], size_t n,
                                   uint8_t *out, size_t outcap);

/* Scan a block message (80-byte header, tx count, then the transactions) into
   (us), applying every transaction at (height). Returns 1, or 0 if malformed. */
int kw_block_scan(const uint8_t *msg, size_t len,
                  kw_utxoset *us, const kw_watchset *ws, uint32_t height);

/* 1 if the transactions in (msg) hash to the merkle root its own header carries.
   Without this a peer serves a genuine header, which is bound to the checked chain by
   its hash, and any body it likes behind it: the header commits to the transactions
   and nothing was checking that it did.

   Rejects a block whose tree has an identical adjacent pair at any level, which is
   CVE-2012-2459: the odd-node duplication rule lets two different transaction lists
   produce one root, so a valid block can be replayed as an invalid one with the same
   hash. Returns 0 on a malformed body too. */
int kw_block_merkle_ok(const uint8_t *msg, size_t len);

/* Download one block by hash over (p) and verify it matches. On success returns
   1 with (payload)/(plen) pointing at peer-owned storage valid until the next
   recv. */
int kw_spv_get_block(kw_peer *p, const uint8_t hash[32],
                     const uint8_t **payload, size_t *plen);

/* Download one block by hash over (p), verify it matches, and scan it into (us)
   at (height). Returns 1 on success, 0 on error. Shared by both backends. */
int kw_spv_fetch_block(kw_peer *p, const uint8_t hash[32],
                       kw_utxoset *us, const kw_watchset *ws, uint32_t height);

/* Whether a block creates or spends one specific outpoint (txid,vout). */
typedef struct { int created; uint64_t created_value; int spent; } kw_outpoint_status;

/* Scan a block message for (txid,vout): set st->created (with created_value) if
   an output at that outpoint exists, and st->spent if an input consumes it.
   Returns 1, or 0 if malformed. */
int kw_block_find_outpoint(const uint8_t *msg, size_t len,
                           const uint8_t txid[32], uint32_t vout, kw_outpoint_status *st);

/* Download and scan every block in the header store over (p), applying to (us).
   The store holds a contiguous chain; (base_height) is the block height of its
   first entry (1 for a from-scratch sync, since genesis is not stored), used to
   tag each UTXO. Verifies each returned block matches the requested hash.
   Returns the number of blocks scanned, or -1 on error. */
long kw_spv_sync_blocks(kw_peer *p, const kw_headerstore *s,
                        kw_utxoset *us, const kw_watchset *ws, uint32_t base_height);

#endif /* KOINU_SPV_H */
