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
    /* Coverage: every element of every vector is in its own filter, which is
       the check a client runs against a block it holds. One element swapped for
       a script that was never in the block has to be reported, and by index, or
       a caller cannot say which output went missing. */
    for (int k = 0; k < KW_BIP158_NVEC; k++) {
        const kw_bip158_vec *v = &KW_BIP158_VECS[k];
        uint8_t filt[4096], hash[32];
        int flen = kw_test_unhex(v->filter, filt);
        kw_test_unhex(v->hash_internal, hash);
        if (v->nelem <= 0) continue;

        static uint8_t ebuf[80][4096];
        kw_gcs_item items[80];
        for (int i = 0; i < v->nelem && i < 80; i++) {
            int el = kw_test_unhex(v->elems[i], ebuf[i]);
            items[i].script = ebuf[i];
            items[i].len = (size_t)el;
        }
        int n = v->nelem < 80 ? v->nelem : 80;
        size_t miss = (size_t)-1;
        if (kw_gcs_covers(filt, (size_t)flen, hash, items, (size_t)n, &miss) != 1) {
            fprintf(stderr, "FAIL: %s does not cover its own elements (index %zu)\n",
                    v->name, miss);
            return 1;
        }

        /* a script the block never had, in a known slot */
        uint8_t bogus[25];
        memset(bogus, 0, sizeof bogus);
        bogus[0] = 0x76; bogus[1] = 0xa9; bogus[2] = 0x14;
        for (int i = 0; i < 20; i++) bogus[3 + i] = (uint8_t)(0xa0 + i + k);
        bogus[23] = 0x88; bogus[24] = 0xac;
        const uint8_t *keep = items[n - 1].script;
        size_t keeplen = items[n - 1].len;
        items[n - 1].script = bogus;
        items[n - 1].len = sizeof bogus;
        miss = (size_t)-1;
        if (kw_gcs_covers(filt, (size_t)flen, hash, items, (size_t)n, &miss) != 0 ||
            miss != (size_t)(n - 1)) {
            fprintf(stderr, "FAIL: %s did not report the missing element (got %zu)\n",
                    v->name, miss);
            return 1;
        }
        items[n - 1].script = keep;
        items[n - 1].len = keeplen;
    }


    /* The encoder, held to the only standard that means anything: rebuild each
       published filter from its own elements and require the bytes to match.
       A filter that merely decodes to the right values could still differ in
       encoding; byte equality leaves nowhere for a mistake to hide. */
    for (int k = 0; k < KW_BIP158_NVEC; k++) {
        const kw_bip158_vec *v = &KW_BIP158_VECS[k];
        uint8_t want[4096], hash[32], got[4096];
        int wlen = kw_test_unhex(v->filter, want);
        kw_test_unhex(v->hash_internal, hash);

        static uint8_t ebuf[80][4096];
        kw_gcs_item items[80];
        int n = v->nelem < 80 ? v->nelem : 80;
        for (int i = 0; i < n; i++) {
            int el = kw_test_unhex(v->elems[i], ebuf[i]);
            items[i].script = ebuf[i];
            items[i].len = (size_t)el;
        }

        long bn = kw_gcs_build(hash, items, (size_t)n, got, sizeof got);
        if (bn < 0) { fprintf(stderr, "FAIL: %s did not build\n", v->name); return 1; }
        if (bn != wlen || memcmp(got, want, (size_t)wlen) != 0) {
            fprintf(stderr, "FAIL: %s rebuilt to %ld bytes, published is %d\n",
                    v->name, bn, wlen);
            return 1;
        }
    }

    /* an empty filter is a lone varint zero, and decodes as none */
    {
        uint8_t hash[32], got[8];
        memset(hash, 0x11, sizeof hash);
        long bn = kw_gcs_build(hash, NULL, 0, got, sizeof got);
        if (bn != 1 || got[0] != 0) {
            fprintf(stderr, "FAIL: the empty filter is %ld bytes\n", bn); return 1;
        }
        uint64_t none[1];
        if (kw_gcs_decode(got, 1, none, 1) != 0) {
            fprintf(stderr, "FAIL: the empty filter did not decode as empty\n"); return 1;
        }
    }

    /* duplicates are one element: N feeds the mapping, so counting a script
       twice would move every value and the filter would match nothing */
    {
        const kw_bip158_vec *v = &KW_BIP158_VECS[0];
        uint8_t hash[32], e[4096], a[4096], b[4096];
        kw_test_unhex(v->hash_internal, hash);
        int el = kw_test_unhex(v->elems[0], e);
        kw_gcs_item one[1] = { { e, (size_t)el } };
        kw_gcs_item two[2] = { { e, (size_t)el }, { e, (size_t)el } };
        long na = kw_gcs_build(hash, one, 1, a, sizeof a);
        long nb = kw_gcs_build(hash, two, 2, b, sizeof b);
        if (na < 1 || na != nb || memcmp(a, b, (size_t)na) != 0) {
            fprintf(stderr, "FAIL: a repeated element changed the filter\n"); return 1;
        }
    }

    /* a buffer too small is refused, not truncated */
    {
        const kw_bip158_vec *v = &KW_BIP158_VECS[0];
        uint8_t hash[32], e[4096], tiny[2];
        kw_test_unhex(v->hash_internal, hash);
        int el = kw_test_unhex(v->elems[0], e);
        kw_gcs_item one[1] = { { e, (size_t)el } };
        if (kw_gcs_build(hash, one, 1, tiny, sizeof tiny) != -1) {
            fprintf(stderr, "FAIL: built into a buffer too small\n"); return 1;
        }
    }

    printf("gcs ok: %d BIP158 vectors, decode == hashed elements, match_any hits and misses,\n"
           "  every vector covers its own elements and a foreign script is reported by index,\n"
           "  and every published filter is rebuilt byte for byte from its own elements\n",
           KW_BIP158_NVEC);
    return 0;
}
