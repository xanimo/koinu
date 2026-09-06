/* koinu.dog - BIP157 message tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * The getcfilters/cfilter wire format, plus an end-to-end check that a real
 * BIP158 filter wrapped in a cfilter message parses and matches its element. */

#include "cf.h"
#include "gcs.h"
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

    printf("cf ok: getcfilters format, cfilter round-trip, real-filter match\n");
    return 0;
}
