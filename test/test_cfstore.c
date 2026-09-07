/* koinu.dog - filter cache tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Append two real BIP158 filters to a cache file, then confirm count, that a
 * matching element is found at its block index, and that an unrelated script
 * is not. Header integrity is exercised by the live path, so (s) is NULL here. */

#include "cfstore.h"
#include "gcs.h"
#include "testutil.h"

#include "bip158_vectors.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    const char *tmp = "test_cfstore.tmp";
    remove(tmp);

    const kw_bip158_vec *a = &KW_BIP158_VECS[2];   /* h49291, 10 elems */
    const kw_bip158_vec *b = &KW_BIP158_VECS[3];   /* h180480, 13 elems */

    uint8_t ha[32], hb[32], fa[256], fb[256];
    kw_test_unhex(a->hash_internal, ha); kw_test_unhex(b->hash_internal, hb);
    int fal = kw_test_unhex(a->filter, fa), fbl = kw_test_unhex(b->filter, fb);

    if (!kw_cfstore_append(tmp, ha, fa, (size_t)fal) ||
        !kw_cfstore_append(tmp, hb, fb, (size_t)fbl)) { fprintf(stderr, "FAIL: append\n"); return 1; }
    if (kw_cfstore_count(tmp) != 2) { fprintf(stderr, "FAIL: count\n"); return 1; }

    /* an element of the first filter is found at index 0 */
    uint8_t elem[4096];
    int elen = kw_test_unhex(a->elems[0], elem);
    kw_gcs_item it = { elem, (size_t)elen };
    uint32_t heights[8];
    long n = kw_cfstore_match(tmp, NULL, 0, &it, 1, heights, 8);
    if (n < 1 || heights[0] != 0) { fprintf(stderr, "FAIL: match (n=%ld)\n", n); return 1; }

    /* an unrelated p2pkh script matches nothing */
    uint8_t bogus[25];
    memset(bogus, 0, sizeof bogus); bogus[0] = 0x76; bogus[1] = 0xa9; bogus[2] = 0x14;
    for (int i = 0; i < 20; i++) bogus[3 + i] = (uint8_t)(0x40 + i);
    bogus[23] = 0x88; bogus[24] = 0xac;
    kw_gcs_item bit = { bogus, sizeof bogus };
    if (kw_cfstore_match(tmp, NULL, 0, &bit, 1, heights, 8) != 0) { fprintf(stderr, "FAIL: false positive\n"); return 1; }

    /* a corrupt tag is rejected */
    FILE *f = fopen(tmp, "r+b"); if (f) { fputc('X', f); fclose(f); }
    if (kw_cfstore_count(tmp) != -1) { fprintf(stderr, "FAIL: corrupt tag accepted\n"); return 1; }
    remove(tmp);

    printf("cfstore ok: append, count, local match hit and miss, corrupt tag rejected\n");
    return 0;
}
