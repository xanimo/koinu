/* koinu.dog - extending the compiled-in filter-header anchors
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "cfanchors.h"
#include "log.h"
#include "hex.h"

#include <string.h>

#define HDR 16          /* tag 4 + version 1 + reserved 3 + magic 4 + count 4 */
#define REC 36          /* height 4 + header 32 */

static const uint8_t TAG[4] = { 'K', 'W', 'C', 'A' };

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

long kw_cfanchors_parse(const uint8_t *buf, size_t buflen, uint32_t magic,
                        kw_cfanchor *out, size_t cap)
{
    if (!buf || !out || buflen < HDR) return -1;
    if (memcmp(buf, TAG, 4) != 0) return -1;
    if (buf[4] != 1) return -1;
    /* Reserved means reserved. A later version that uses these bytes gets a
       version number too, and a reader that ignored them would accept a table
       it does not understand the whole of. */
    if (buf[5] || buf[6] || buf[7]) return -1;
    if (rd32(buf + 8) != magic) return -1;

    uint32_t n = rd32(buf + 12);
    if (n == 0 || n > KW_CFANCHORS_MAX || n > cap) return -1;
    /* The length has to come from the buffer, not from the count: a count that
       overruns is the whole of what a length field is for. Exact rather than at
       least, so trailing bytes are a malformed table rather than something to
       skip past without knowing what it was. */
    if (buflen != (size_t)HDR + (size_t)n * REC) return -1;

    uint32_t prev = 0;
    for (uint32_t i = 0; i < n; i++) {
        const uint8_t *r = buf + HDR + (size_t)i * REC;
        uint32_t h = rd32(r);
        /* Strictly ascending, so a table cannot hold one height twice and leave
           which of the two is believed to the order a reader walks it in. */
        if (h == 0 || h <= prev) return -1;
        prev = h;
        out[i].height = h;
        memcpy(out[i].header, r + 4, 32);
    }
    return (long)n;
}

/* The compiled anchor at (height), or NULL. Display hex in, internal order out,
   which is the one place this file touches chainparams' encoding. */
static int compiled_at(const kw_chainparams *cp, uint32_t height, uint8_t out[32])
{
    for (size_t i = 0; i < cp->ncfcheckpoints; i++) {
        if (cp->cfcheckpoints[i].height != height) continue;
        uint8_t disp[32];
        if (!cp->cfcheckpoints[i].header ||
            !kw_hex_decode(cp->cfcheckpoints[i].header, 64, disp, sizeof disp)) return 0;
        for (int k = 0; k < 32; k++) out[k] = disp[31 - k];
        return 1;
    }
    return 0;
}

static uint32_t newest_compiled(const kw_chainparams *cp)
{
    uint32_t best = 0;
    for (size_t i = 0; i < cp->ncfcheckpoints; i++)
        if (cp->cfcheckpoints[i].height > best) best = cp->cfcheckpoints[i].height;
    return best;
}

int kw_cfanchors_extends(const kw_chainparams *cp, const kw_cfanchor *cand, size_t n,
                         uint32_t *from_height)
{
    if (!cp || !cand || !n) return 0;

    /* A network pinning nothing has no floor to extend and nothing to check a
       candidate against, so there is no answer this could give that means
       anything. Refused rather than waved through. */
    if (!cp->ncfcheckpoints) {
        kw_logf(KW_LOG_ERROR, "this network pins no filter anchors, so there is nothing "
                              "to check a fetched table against");
        return 0;
    }

    uint32_t newest = newest_compiled(cp);
    uint32_t first_new = 0;
    int overlap = 0;

    for (size_t i = 0; i < n; i++) {
        uint8_t want[32];
        if (compiled_at(cp, cand[i].height, want)) {
            if (memcmp(want, cand[i].header, 32) != 0) {
                kw_logf(KW_LOG_ERROR, "a fetched anchor table disagrees with this release "
                                      "at height %u, so none of it is believed",
                        cand[i].height);
                return 0;
            }
            overlap = 1;
            continue;
        }
        /* Below the floor and not a height this release pins. Accepting it
           would let a fetch introduce a pin the binary never agreed to, which
           is the one direction this is built to refuse. The compiled table
           stands on its own there, so ignoring it costs nothing. */
        if (cand[i].height <= newest) continue;
        if (!first_new) first_new = cand[i].height;
    }

    if (!overlap) {
        kw_logf(KW_LOG_ERROR, "a fetched anchor table shares no height with this release, "
                              "so nothing in it can be checked");
        return 0;
    }
    if (!first_new) {
        kw_logf(KW_LOG_ERROR, "a fetched anchor table reaches no higher than %u, which "
                              "this release already pins", newest);
        return 0;
    }
    if (from_height) *from_height = first_new;
    return 1;
}
