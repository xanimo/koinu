/* koinu.dog - BIP158 basic filter tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * For each official vector: decode the filter, independently hash the element
 * set, and require the two sorted value lists to be identical, then require
 * match_any to find each element and to miss a script not in the set. */

#include "gcs.h"
#include "testutil.h"

#include "bip158_vectors.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

int main(void)
{
    for (int vi = 0; vi < KW_BIP158_NVEC; vi++) {
        const kw_bip158_vec *v = &KW_BIP158_VECS[vi];

        uint8_t hash[32];
        if (kw_test_unhex(v->hash_internal, hash) != 32) { fprintf(stderr, "FAIL: %s hash\n", v->name); return 1; }
        uint8_t filt[256];
        int flen = kw_test_unhex(v->filter, filt);
        if (flen < 0) { fprintf(stderr, "FAIL: %s filter hex\n", v->name); return 1; }

        uint64_t dec[128];
        long N = kw_gcs_decode(filt, (size_t)flen, dec, 128);
        if (N != v->nelem) { fprintf(stderr, "FAIL: %s N %ld != %d\n", v->name, N, v->nelem); return 1; }

        /* independent path: hash each element, sort, compare to the decode */
        uint64_t mine[128];
        uint8_t elem[4096];
        for (int i = 0; i < v->nelem; i++) {
            int elen = kw_test_unhex(v->elems[i], elem);
            if (elen < 0) { fprintf(stderr, "FAIL: %s elem hex\n", v->name); return 1; }
            mine[i] = kw_gcs_hash(hash, (uint64_t)N, elem, (size_t)elen);
        }
        qsort(mine, (size_t)v->nelem, sizeof *mine, cmp_u64);
        for (int i = 0; i < v->nelem; i++)
            if (mine[i] != dec[i]) { fprintf(stderr, "FAIL: %s value %d\n", v->name, i); return 1; }

        /* match_any finds every element */
        for (int i = 0; i < v->nelem; i++) {
            int elen = kw_test_unhex(v->elems[i], elem);
            kw_gcs_item it = { elem, (size_t)elen };
            if (kw_gcs_match_any(filt, (size_t)flen, hash, &it, 1) != 1) {
                fprintf(stderr, "FAIL: %s element %d not matched\n", v->name, i); return 1;
            }
        }

        /* a script not in the set does not match (empty filter never matches) */
        uint8_t bogus[25];
        memset(bogus, 0x00, sizeof bogus); bogus[0] = 0x76; bogus[1] = 0xa9; bogus[2] = 0x14;
        for (int i = 0; i < 20; i++) bogus[3 + i] = (uint8_t)(0xde + i);
        bogus[23] = 0x88; bogus[24] = 0xac;
        kw_gcs_item bit = { bogus, sizeof bogus };
        if (kw_gcs_match_any(filt, (size_t)flen, hash, &bit, 1) != 0) {
            fprintf(stderr, "FAIL: %s false positive\n", v->name); return 1;
        }
    }

    printf("gcs ok: %d BIP158 vectors, decode == hashed elements, match_any hits and misses\n",
           KW_BIP158_NVEC);
    return 0;
}
