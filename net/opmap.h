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
 * Only the script is kept, since a filter needs neither the value, the height
 * nor the coinbase flag. That was argued here as roughly halving the cost
 * against Core's chainstate and it does not: measured on dogecoin mainnet at
 * height 6429620, Core holds 202671977 outputs in 13636287062 bytes, which is
 * 67.3 an entry, and this map carries the script alone for 67.1. Core already
 * compresses a script to a type byte and 20 bytes and an amount to a
 * variable-length field, so there was nothing to win. The comparison was
 * against an uncompressed chainstate that does not exist.
 *
 * Not a validating index either. Nothing here checks a signature or a consensus
 * rule; it records what the chain says so filters can be built from it. An
 * indexer is not a node.
 *
 * Memory, measured rather than estimated: a slot is 48 bytes and the table runs
 * to three quarters full, so 3000000 entries occupied 4194304 slots for 201 MB,
 * which is 67 bytes an entry. A growth doubles the table and the old one is
 * still mapped while it is rehashed, so peak is about 1.5 times the steady
 * figure: that run peaked at 296 MB of RSS.
 *
 *     20M outputs   1.3 GB steady   2.0 GB peak
 *     50M           3.4 GB          5.0 GB
 *    100M           6.7 GB         10.1 GB
 *    203M          13.6 GB         20.4 GB    <- dogecoin mainnet, measured
 *
 * At the real count an in-memory map is not viable: 13.6 GB of RAM to hold what
 * Core holds in 13.6 GB of disk behind a cache. Doing better means a disk-backed
 * store, which is reimplementing a chainstate, and the chain itself is 203.5 GB
 * to fetch before any of it starts. So this is useful on regtest, on testnet and
 * over a bounded range, and it is not the way to generate mainnet filters. The
 * way to more filter providers is BIP157 in Core, not a second chainstate here.
 *
 * Two things would cut it when the count is known. Presizing removes the growth
 * spike and the repeated rehashing outright. Shrinking the key to 12 bytes and
 * folding the overflow index into the script bytes takes the slot to 40, which
 * with a higher load factor is nearer 47 bytes an entry. Neither is worth doing
 * before the measurement says what is being optimised for. */

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
