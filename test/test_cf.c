/* koinu.dog - BIP157 message tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * The getcfilters/cfilter wire format, plus an end-to-end check that a real
 * BIP158 filter wrapped in a cfilter message parses and matches its element. */

#include "cf.h"
#include "gcs.h"
#include "sha2.h"
#include "testutil.h"

#include "bip158_vectors.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    /* getcfilters: type, start height (LE), stop hash */
    {
        uint8_t stop[32];
        for (int i = 0; i < 32; i++) stop[i] = (uint8_t)(i + 1);
        uint8_t out[37];
        size_t n = kw_msg_getcfilters_build(KW_CF_TYPE_BASIC, 0x01020304, stop, out, sizeof out);
        if (n != 37) { fprintf(stderr, "FAIL: getcfilters len %zu\n", n); return 1; }
        if (out[0] != 0x00 || out[1] != 0x04 || out[2] != 0x03 || out[3] != 0x02 || out[4] != 0x01) {
            fprintf(stderr, "FAIL: getcfilters head\n"); return 1;
        }
        if (memcmp(out + 5, stop, 32) != 0) { fprintf(stderr, "FAIL: getcfilters stop\n"); return 1; }
        if (kw_msg_getcfilters_build(0, 0, stop, out, 36) != 0) { fprintf(stderr, "FAIL: short cap\n"); return 1; }
    }

    /* cfilter round-trip using a real filter, and it matches its own element */
    {
        const kw_bip158_vec *v = &KW_BIP158_VECS[2];   /* h49291: 10 elements */
        uint8_t hash[32]; kw_test_unhex(v->hash_internal, hash);
        uint8_t filt[256]; int flen = kw_test_unhex(v->filter, filt);

        uint8_t msg[512]; size_t n = 0;
        msg[n++] = KW_CF_TYPE_BASIC;
        memcpy(msg + n, hash, 32); n += 32;
        msg[n++] = (uint8_t)flen;                       /* filter under 253 bytes */
        memcpy(msg + n, filt, (size_t)flen); n += (size_t)flen;

        uint8_t type, bh[32]; const uint8_t *pf; size_t pfl;
        if (!kw_msg_cfilter_parse(msg, n, &type, bh, &pf, &pfl)) { fprintf(stderr, "FAIL: cfilter parse\n"); return 1; }
        if (type != KW_CF_TYPE_BASIC || memcmp(bh, hash, 32) != 0 || pfl != (size_t)flen ||
            memcmp(pf, filt, pfl) != 0) { fprintf(stderr, "FAIL: cfilter fields\n"); return 1; }

        uint8_t elem[4096];
        int elen = kw_test_unhex(v->elems[0], elem);
        kw_gcs_item it = { elem, (size_t)elen };
        if (kw_gcs_match_any(pf, pfl, bh, &it, 1) != 1) { fprintf(stderr, "FAIL: cfilter no match\n"); return 1; }

        /* a truncated cfilter is rejected */
        if (kw_msg_cfilter_parse(msg, 20, &type, bh, &pf, &pfl)) { fprintf(stderr, "FAIL: short cfilter\n"); return 1; }
    }

    /* cfheaders: type, stop, previous filter header, then the filter hashes */
    {
        uint8_t stop[32], prev[32], h1[32], h2[32];
        memset(stop, 0xaa, 32); memset(prev, 0xbb, 32);
        memset(h1, 0x01, 32); memset(h2, 0x02, 32);
        uint8_t msg[130]; size_t n = 0;
        msg[n++] = KW_CF_TYPE_BASIC;
        memcpy(msg + n, stop, 32); n += 32;
        memcpy(msg + n, prev, 32); n += 32;
        msg[n++] = 2;
        memcpy(msg + n, h1, 32); n += 32;
        memcpy(msg + n, h2, 32); n += 32;

        uint8_t type, ps[32], pp[32]; const uint8_t *hs; size_t nh;
        if (!kw_msg_cfheaders_parse(msg, n, &type, ps, pp, &hs, &nh)) { fprintf(stderr, "FAIL: cfheaders parse\n"); return 1; }
        if (type != KW_CF_TYPE_BASIC || nh != 2 || memcmp(ps, stop, 32) != 0 ||
            memcmp(pp, prev, 32) != 0 || memcmp(hs, h1, 32) != 0 || memcmp(hs + 32, h2, 32) != 0) {
            fprintf(stderr, "FAIL: cfheaders fields\n"); return 1;
        }
        /* truncation and a count beyond the payload are rejected */
        if (kw_msg_cfheaders_parse(msg, n - 1, &type, ps, pp, &hs, &nh)) { fprintf(stderr, "FAIL: short cfheaders\n"); return 1; }
        msg[65] = 3;
        if (kw_msg_cfheaders_parse(msg, n, &type, ps, pp, &hs, &nh)) { fprintf(stderr, "FAIL: overlong count\n"); return 1; }
    }

    /* the filter-header chain step reproduces every official vector */
    for (size_t i = 0; i < sizeof KW_BIP158_VECS / sizeof KW_BIP158_VECS[0]; i++) {
        const kw_bip158_vec *v = &KW_BIP158_VECS[i];
        uint8_t filt[256]; int flen = kw_test_unhex(v->filter, filt);
        uint8_t prev[32], want[32]; kw_test_unhex(v->prev_header, prev); kw_test_unhex(v->header, want);
        uint8_t fhash[32], got[32];
        kw_hash256(filt, (size_t)flen, fhash);
        kw_cf_header_step(fhash, prev, got);
        if (memcmp(got, want, 32) != 0) { fprintf(stderr, "FAIL: header chain %s\n", v->name); return 1; }
    }

    printf("cf ok: getcfilters format, cfilter round-trip, real-filter match, cfheaders parse, header chain vectors\n");
    return 0;
}
