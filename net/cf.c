/* koinu.dog - BIP157 compact-filter sync
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "cf.h"
#include "gcs.h"
#include "spv.h"
#include "sync.h"
#include "cfstore.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

size_t kw_msg_getcfilters_build(uint8_t type, uint32_t start_height,
                                const uint8_t stop_hash[32], uint8_t *out, size_t outcap)
{
    if (outcap < 1 + 4 + 32) return 0;
    out[0] = type;
    for (int i = 0; i < 4; i++) out[1 + i] = (uint8_t)(start_height >> (8 * i));
    memcpy(out + 5, stop_hash, 32);
    return 1 + 4 + 32;
}

int kw_msg_cfilter_parse(const uint8_t *payload, size_t len,
                         uint8_t *type, uint8_t block_hash[32],
                         const uint8_t **filter, size_t *flen)
{
    if (len < 1 + 32 + 1) return 0;
    *type = payload[0];
    memcpy(block_hash, payload + 1, 32);

    size_t off = 33;
    uint8_t pfx = payload[off++];
    uint64_t n;
    if (pfx < 0xfd) n = pfx;
    else {
        int k = pfx == 0xfd ? 2 : pfx == 0xfe ? 4 : 8;
        if (off + (size_t)k > len) return 0;
        n = 0;
        for (int i = 0; i < k; i++) n |= (uint64_t)payload[off + i] << (8 * i);
        off += (size_t)k;
    }
    if (n > (uint64_t)(len - off)) return 0;
    *filter = payload + off;
    *flen = (size_t)n;
    return 1;
}

long kw_cf_sync(kw_peer *p, const kw_headerstore *s,
                kw_utxoset *us, const kw_watchset *ws, uint32_t base_height)
{
    if (s->count == 0) return 0;

    kw_gcs_item *items = NULL;
    if (ws->count) {
        items = (kw_gcs_item *)malloc(ws->count * sizeof *items);
        if (!items) return -1;
        for (size_t i = 0; i < ws->count; i++) {
            items[i].script = ws->w[i].spk;
            items[i].len = ws->w[i].len;
        }
    }

    size_t *matched = NULL, nm = 0, capm = 0;
    int err = 0;
    const size_t CHUNK = 1000;                 /* BIP157 caps a request at 1000 */

    for (size_t s0 = 0; s0 < s->count && !err; s0 += CHUNK) {
        size_t s1 = s0 + CHUNK;
        if (s1 > s->count) s1 = s->count;

        uint8_t body[37];
        size_t bn = kw_msg_getcfilters_build(KW_CF_TYPE_BASIC, base_height + (uint32_t)s0,
                                             s->h[s1 - 1].hash, body, sizeof body);
        if (!bn || !kw_peer_send(p, "getcfilters", body, bn)) { err = 1; break; }

        for (size_t k = s0; k < s1 && !err; k++) {
            char cmd[13]; const uint8_t *pl = NULL; size_t pn = 0;
            int got = 0;
            while (kw_peer_recv(p, cmd, &pl, &pn) == 1) {
                if (!strcmp(cmd, "cfilter")) { got = 1; break; }
                if (!strcmp(cmd, "ping")) kw_peer_send(p, "pong", pl, pn);
            }
            if (!got) { err = 1; break; }

            uint8_t type, bh[32]; const uint8_t *filt; size_t flen;
            if (!kw_msg_cfilter_parse(pl, pn, &type, bh, &filt, &flen)) { err = 1; break; }
            /* filters arrive in height order; each must be the block we expect */
            if (type != KW_CF_TYPE_BASIC || memcmp(bh, s->h[k].hash, 32) != 0) { err = 1; break; }

            int m = ws->count ? kw_gcs_match_any(filt, flen, bh, items, ws->count) : 0;
            if (m < 0) { err = 1; break; }
            if (m == 1) {
                if (nm == capm) {
                    size_t nc = capm ? capm * 2 : 16;
                    size_t *t = (size_t *)realloc(matched, nc * sizeof *t);
                    if (!t) { err = 1; break; }
                    matched = t; capm = nc;
                }
                matched[nm++] = k;
                if (kw_net_verbose)
                    fprintf(stderr, "[cf] match at height %u\n", base_height + (uint32_t)k);
            }
        }
        if (kw_net_verbose)
            fprintf(stderr, "[cf] checked %zu/%zu filters, %zu matched\n",
                    s1, s->count, nm);
    }

    long scanned = -1;
    if (!err) {
        scanned = 0;
        for (size_t i = 0; i < nm; i++) {
            size_t k = matched[i];
            if (!kw_spv_fetch_block(p, s->h[k].hash, us, ws, base_height + (uint32_t)k)) {
                scanned = -1; break;
            }
            scanned++;
        }
    }

    free(items);
    free(matched);
    return scanned;
}

long kw_cf_scan_cached(kw_peer *p, const kw_headerstore *s,
                       kw_utxoset *us, const kw_watchset *ws, uint32_t base_height,
                       const char *filters_path)
{
    if (kw_cfstore_sync(p, s, filters_path, base_height) < 0) return -1;
    if (s->count == 0) return 0;

    kw_gcs_item *items = NULL;
    if (ws->count) {
        items = (kw_gcs_item *)malloc(ws->count * sizeof *items);
        if (!items) return -1;
        for (size_t i = 0; i < ws->count; i++) { items[i].script = ws->w[i].spk; items[i].len = ws->w[i].len; }
    }

    uint32_t *heights = (uint32_t *)malloc(s->count * sizeof *heights);
    if (!heights) { free(items); return -1; }
    long nm = kw_cfstore_match(filters_path, s, base_height, items, ws->count, heights, s->count);
    free(items);
    if (nm < 0) { free(heights); return -1; }

    long scanned = 0;
    for (long i = 0; i < nm; i++) {
        size_t idx = heights[i] - base_height;
        if (!kw_spv_fetch_block(p, s->h[idx].hash, us, ws, heights[i])) { free(heights); return -1; }
        scanned++;
    }
    free(heights);
    return scanned;
}

int kw_query_outpoint_range(kw_peer *p, const kw_headerstore *s, const char *filters_path,
                            uint32_t base_height, const uint8_t *spk, size_t spklen,
                            const uint8_t txid[32], uint32_t vout, uint32_t since,
                            kw_outpoint_result *res)
{
    if (kw_cfstore_sync(p, s, filters_path, base_height) < 0) return -1;

    kw_gcs_item it = { spk, spklen };
    uint32_t *heights = (uint32_t *)malloc((s->count ? s->count : 1) * sizeof *heights);
    if (!heights) return -1;
    long nm = kw_cfstore_match_range(filters_path, s, base_height, since, &it, 1, heights, s->count);
    if (nm < 0) { free(heights); return -1; }

    long created_h = -1, spent_h = -1; uint64_t value = 0;
    for (long i = 0; i < nm; i++) {
        size_t idx = heights[i] - base_height;
        const uint8_t *pl = NULL; size_t pn = 0;
        kw_outpoint_status st = { 0, 0, 0 };
        if (!kw_spv_get_block(p, s->h[idx].hash, &pl, &pn) ||
            !kw_block_find_outpoint(pl, pn, txid, vout, &st)) { free(heights); return -1; }
        if (st.created) { created_h = (long)heights[i]; value = st.created_value; }
        if (st.spent) spent_h = (long)heights[i];
    }
    free(heights);

    res->tipheight = (long)base_height + (long)s->count - 1;
    res->value = 0; res->height = 0;
    if (spent_h >= 0) { res->status = 1; res->height = spent_h; }
    else if (created_h >= 0) { res->status = 0; res->height = created_h; res->value = value; }
    else res->status = 2;
    return 1;
}
