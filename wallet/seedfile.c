/* koinu.dog - what a keystore holds besides the seed
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "seedfile.h"
#include "mem.h"

#include <string.h>

/* "KWB1" after the seed. A tag rather than a bare length because the seed is
   fixed at 64 and anything following it is this project's to define: a reader
   that finds something else should refuse rather than guess at a layout, and a
   later field set gets KWB2 without the two being mistakable. */
static const uint8_t KWB1[4] = { 'K', 'W', 'B', '1' };

size_t kw_seedfile_pack(const uint8_t seed[KW_SEED_LEN], const kw_birthday *birth,
                        uint8_t *out, size_t outcap)
{
    if (!seed || !out) return 0;

    int carry = birth && birth->height;
    size_t need = KW_SEED_LEN + (carry ? 40u : 0u);
    if (outcap < need) return 0;

    memcpy(out, seed, KW_SEED_LEN);
    if (!carry) return KW_SEED_LEN;

    memcpy(out + KW_SEED_LEN, KWB1, 4);
    uint32_t h = birth->height;
    for (int i = 0; i < 4; i++) out[KW_SEED_LEN + 4 + i] = (uint8_t)(h >> (8 * i));
    memcpy(out + KW_SEED_LEN + 8, birth->hash, 32);
    return need;
}

int kw_seedfile_unpack(const uint8_t *blob, size_t bloblen,
                       uint8_t seed[KW_SEED_LEN], kw_birthday *birth)
{
    if (!blob || !seed) return 0;
    if (birth) { birth->height = 0; memset(birth->hash, 0, 32); }

    /* Written before this existed. The seed is the whole secret and there is no
       birthday to find, which is not an error: such a wallet scans from wherever
       its caller starts, the same as it always did. */
    if (bloblen == KW_SEED_LEN) {
        memcpy(seed, blob, KW_SEED_LEN);
        return 1;
    }
    if (bloblen != KW_SEED_LEN + 40) return 0;
    if (memcmp(blob + KW_SEED_LEN, KWB1, 4) != 0) return 0;

    uint32_t h = 0;
    for (int i = 0; i < 4; i++) h |= (uint32_t)blob[KW_SEED_LEN + 4 + i] << (8 * i);
    /* A trailer that says height 0 is a contradiction: pack writes no trailer
       for that, so somebody built this blob by hand or truncated a field. */
    if (!h) return 0;

    memcpy(seed, blob, KW_SEED_LEN);
    if (birth) { birth->height = h; memcpy(birth->hash, blob + KW_SEED_LEN + 8, 32); }
    return 1;
}
