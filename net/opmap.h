/* koinu.dog - outpoint to scriptPubKey, for generating filters
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * A basic filter carries the scripts a block spends, and an input names only
 * the outpoint it consumes. Resolving those needs a map from outpoint to
 * script over every unspent output, which is why filters come from nodes.
 *
 * But a machine that walks blocks in order has already seen every prevout it
 * will ever need: an input always spends an output created earlier. So the map
 * is not extra information, it is bookkeeping, and keeping it is the whole
 * difference between consuming filters and producing them.
 *
 * This is deliberately not a chainstate. Core's carries the value, the height
 * and the coinbase flag per entry, and a filter needs none of them. Only the
 * script is kept, which is the one field that matters here and roughly halves
 * the cost before any packing.
 *
 * Not a validating index either. Nothing here checks a signature or a consensus
 * rule; it records what the chain says so filters can be built from it. An
 * indexer is not a node.
 *
 * Memory: an entry is a 16-byte outpoint digest plus 21 bytes of script, and
 * the table runs at up to three quarters full, so a set of n outputs costs
 * roughly 50n bytes. The real figure needs the real UTXO count, which only a
 * node can give. The structure is replaceable if that number says it must be. */

#ifndef KOINU_OPMAP_H
#define KOINU_OPMAP_H

#include <stddef.h>
#include <stdint.h>

/* The 36 bytes an input carries: txid in internal order, then the index little
   endian. kw_block_spent_outpoints hands them over in exactly this shape. */
#define KW_OPMAP_OUTPOINT 36

/* The longest script kept inline. P2PKH is 25 and P2SH 23, which is nearly
   everything on this chain; anything longer is held to one side. */
#define KW_OPMAP_INLINE 25

typedef struct kw_opmap kw_opmap;

/* An empty map. NULL on allocation failure; free takes NULL. */
kw_opmap *kw_opmap_new(void);
void      kw_opmap_free(kw_opmap *m);

/* Record that (op) pays (spk). Replaces any entry already there, because a
   chain cannot create the same outpoint twice and an attempt to means the
   caller is feeding blocks out of order. Returns 1, or 0 out of memory or on a
   script longer than this keeps. */
int kw_opmap_put(kw_opmap *m, const uint8_t op[KW_OPMAP_OUTPOINT],
                 const uint8_t *spk, size_t spklen);

/* The script (op) pays, removing the entry: a spend consumes it, and an
   outpoint is spent once. Writes at most (cap) bytes and the true length to
   (len). Returns 1 if it was there, 0 if not.
 *
 * Lookup and removal are one call because every caller wants both, and a map
 * that let them drift would keep spent outputs alive and put their scripts in
 * filters they do not belong in. */
int kw_opmap_take(kw_opmap *m, const uint8_t op[KW_OPMAP_OUTPOINT],
                  uint8_t *spk, size_t cap, size_t *len);

/* How many unspent outputs are held. */
size_t kw_opmap_count(const kw_opmap *m);

/* Slots allocated, for reporting what the map costs. */
size_t kw_opmap_capacity(const kw_opmap *m);

#endif /* KOINU_OPMAP_H */
