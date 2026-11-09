/* koinu.dog - what a keystore holds besides the seed
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * kw_keystore_seal takes opaque bytes and authenticates every one of them, so
 * anything a wallet needs to carry alongside its seed belongs inside that blob
 * rather than in a second file or a wider keystore header. This is the layout
 * of those bytes.
 *
 * A wallet created at a known height need never look below it: nothing can pay
 * an address derived from a seed that did not exist yet. Without the height a
 * restore has to consider every block, because nothing tells it otherwise, and
 * on a phone that is the difference between a first scan that finishes and one
 * that does not. */

#ifndef KOINU_SEEDFILE_H
#define KOINU_SEEDFILE_H

#include <stddef.h>
#include <stdint.h>

#define KW_SEED_LEN 64

/* The height alone cannot be checked against anything. With the hash of the
   block at that height a scan can say whether the birthday names a block on the
   chain it is syncing, so a keystore carried to another network, or one whose
   birthday was reorged out, is caught rather than silently scanning from a
   point that was never on this chain.

   height 0 means no birthday: either a keystore written before this existed, or
   one created without a height to record. Block 0 is the genesis block and no
   wallet is older than it, so it is not a height anybody loses by spending. */
typedef struct {
    uint32_t height;
    uint8_t  hash[32];       /* internal byte order, as the header store holds it */
} kw_birthday;

/* Bytes to seal for (seed), plus (birth) when its height is nonzero. */
#define KW_SEEDFILE_MAX (KW_SEED_LEN + 40)

size_t kw_seedfile_pack(const uint8_t seed[KW_SEED_LEN], const kw_birthday *birth,
                        uint8_t *out, size_t outcap);

/* Read back what pack wrote. A blob of exactly KW_SEED_LEN is a keystore from
   before this existed and opens with height 0, which is the whole of the
   compatibility story: the length distinguishes them and no version byte is
   needed for the old case because the old case has no bytes to spare.
   Returns 1, or 0 if the blob is not a seed this understands. (birth) may be
   NULL. */
int kw_seedfile_unpack(const uint8_t *blob, size_t bloblen,
                       uint8_t seed[KW_SEED_LEN], kw_birthday *birth);

#endif /* KOINU_SEEDFILE_H */
