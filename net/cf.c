/* koinu.dog - BIP157 compact-filter sync
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "cf.h"
#include "gcs.h"
#include "spv.h"
#include "sync.h"
#include "cfstore.h"
#include "sha2.h"

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

size_t kw_msg_getcfheaders_build(uint8_t type, uint32_t start_height,
                                 const uint8_t stop_hash[32], uint8_t *out, size_t outcap)
{
    return kw_msg_getcfilters_build(type, start_height, stop_hash, out, outcap);
}

int kw_msg_cfheaders_parse(const uint8_t *payload, size_t len,
                           uint8_t *type, uint8_t stop_hash[32], uint8_t prev_header[32],
                           const uint8_t **hashes, size_t *nhashes)
{
    if (len < 1 + 32 + 32 + 1) return 0;
    *type = payload[0];
    memcpy(stop_hash, payload + 1, 32);
    memcpy(prev_header, payload + 33, 32);

    size_t off = 65;
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
    if (n > (uint64_t)((len - off) / 32) || n * 32 != len - off) return 0;
    *hashes = payload + off;
    *nhashes = (size_t)n;
    return 1;
}

void kw_cf_header_step(const uint8_t filter_hash[32], const uint8_t prev[32], uint8_t out[32])
{
    uint8_t buf[64];
    memcpy(buf, filter_hash, 32);
    memcpy(buf + 32, prev, 32);
    kw_hash256(buf, 64, out);
}

/* display (reversed) hex to internal order, as the checkpoint tables store it */
static int unhex_rev(const char *hex, uint8_t out[32])
{
    for (int i = 0; i < 32; i++) {
        int hi = -1, lo = -1;
        char a = hex[2 * i], b = hex[2 * i + 1];
        if (a >= '0' && a <= '9') hi = a - '0'; else if (a >= 'a' && a <= 'f') hi = a - 'a' + 10;
        else if (a >= 'A' && a <= 'F') hi = a - 'A' + 10;
        if (b >= '0' && b <= '9') lo = b - '0'; else if (b >= 'a' && b <= 'f') lo = b - 'a' + 10;
        else if (b >= 'A' && b <= 'F') lo = b - 'A' + 10;
        if (hi < 0 || lo < 0) return 0;
        out[31 - i] = (uint8_t)((hi << 4) | lo);
    }
    return hex[64] == '\0';
}

/* The filter-header anchor at (height), or NULL. */
static const kw_cfcheckpoint *cf_anchor_at(const kw_chainparams *cp, uint32_t height)
{
    if (!cp || !cp->cfcheckpoints) return NULL;
    for (size_t i = 0; i < cp->ncfcheckpoints; i++)
        if (cp->cfcheckpoints[i].height == height) return &cp->cfcheckpoints[i];
    return NULL;
}

int kw_cf_anchor_ok(const kw_chainparams *cp, uint32_t height, const uint8_t chain[32])
{
    const kw_cfcheckpoint *a = cf_anchor_at(cp, height);
    uint8_t want[32];
    if (!a || !unhex_rev(a->header, want)) return 1;
    if (memcmp(chain, want, 32) == 0) {
        if (kw_net_verbose) fprintf(stderr, "[cf] filter-header anchor %u matched\n", height);
        return 1;
    }
    fprintf(stderr, "kw: filter-header anchor mismatch at height %u; "
                    "this peer's filters are not the ones this release pins\n", height);
    return 0;
}

int kw_cf_fetch_headers(kw_peer *p, const kw_headerstore *s, uint32_t base_height,
                        size_t s0, size_t s1, uint8_t prev[32], uint8_t (*hashes)[32])
{
    uint8_t body[37];
    size_t bn = kw_msg_getcfheaders_build(KW_CF_TYPE_BASIC, base_height + (uint32_t)s0,
                                          s->h[s1 - 1].hash, body, sizeof body);
    if (!bn || !kw_peer_send(p, "getcfheaders", body, bn)) return 0;

    char cmd[13]; const uint8_t *pl = NULL; size_t pn = 0;
    for (;;) {
        if (kw_peer_recv(p, cmd, &pl, &pn) != 1) return 0;
        if (!strcmp(cmd, "cfheaders")) break;
        if (!strcmp(cmd, "ping")) kw_peer_send(p, "pong", pl, pn);
    }

    uint8_t type, stop[32]; const uint8_t *hp; size_t nh;
    if (!kw_msg_cfheaders_parse(pl, pn, &type, stop, prev, &hp, &nh)) return 0;
    if (type != KW_CF_TYPE_BASIC || nh != s1 - s0 ||
        memcmp(stop, s->h[s1 - 1].hash, 32) != 0) return 0;
    memcpy(hashes, hp, nh * 32);            /* the recv buffer dies on the next recv */
    return 1;
}

/* A peer that does not advertise BIP157 will not answer getcfheaders, and the
   caller otherwise learns that as a wire timeout. Said once, plainly. */
static void warn_no_filters(const kw_peer *p)
{
    if (p && p->peer_services && !(p->peer_services & KW_NODE_COMPACT_FILTERS))
        fprintf(stderr, "kw: this peer does not serve compact filters (services %#llx); "
                        "use --spv, or a node with filters enabled\n",
                (unsigned long long)p->peer_services);
}

long kw_cf_sync(kw_peer *p, const kw_headerstore *s,
                kw_utxoset *us, const kw_watchset *ws, uint32_t base_height)
{
    if (s->count == 0) return 0;
    warn_no_filters(p);

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

    uint8_t (*fh)[32] = (uint8_t (*)[32])malloc(CHUNK * 32);
    if (!fh) { free(items); return -1; }
    uint8_t chain[32]; int have_chain = 0;

    for (size_t s0 = 0; s0 < s->count && !err; s0 += CHUNK) {
        size_t s1 = s0 + CHUNK;
        if (s1 > s->count) s1 = s->count;

        /* the committed filter-header chain first, then the filters it binds */
        uint8_t prev[32];
        if (!kw_cf_fetch_headers(p, s, base_height, s0, s1, prev, fh)) { err = 1; break; }
        if (have_chain && memcmp(prev, chain, 32) != 0) {
            if (kw_net_verbose) fprintf(stderr, "[cf] filter-header chain broke at height %u\n",
                                        base_height + (uint32_t)s0);
            err = 1; break;
        }
        /* prev is the chain as of base_height+s0-1, so an anchor there bounds where
           this chunk starts; without it the base is only ever what the peer said. */
        if (s0 > 0 && !kw_cf_anchor_ok(p->cp, base_height + (uint32_t)s0 - 1, prev)) { err = 1; break; }
        memcpy(chain, prev, 32); have_chain = 1;

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

            uint8_t fhash[32];
            kw_hash256(filt, flen, fhash);
            if (memcmp(fhash, fh[k - s0], 32) != 0) {
                if (kw_net_verbose) fprintf(stderr, "[cf] filter commitment mismatch at height %u\n",
                                            base_height + (uint32_t)k);
                err = 1; break;
            }
            kw_cf_header_step(fhash, chain, chain);
            if (!kw_cf_anchor_ok(p->cp, base_height + (uint32_t)k, chain)) { err = 1; break; }

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

    free(fh);
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
    uint32_t *heights = (uint32_t *)malloc((s->count ? s->count : 1) * sizeof *heights);
    if (!heights) return -1;

    long nm;
    if (filters_path) {
        if (kw_cfstore_sync(p, s, filters_path, base_height) < 0) { free(heights); return -1; }
        kw_gcs_item it = { spk, spklen };
        nm = kw_cfstore_match_range(filters_path, s, base_height, since, &it, 1, heights, s->count);
        if (nm < 0) { free(heights); return -1; }
    } else {
        /* No filters, so every block in the range is a candidate. A filter only
           ever narrowed which blocks to fetch; the block is what answers the
           question either way. Bounded by (since), which is what makes this
           usable on a chain where no peer serves filters at all. */
        (void)spk; (void)spklen;
        nm = 0;
        for (size_t i = 0; i < s->count; i++) {
            uint32_t h = base_height + (uint32_t)i;
            if (h >= since) heights[nm++] = h;
        }
        if (kw_net_verbose)
            fprintf(stderr, "[spv] no filters, fetching %ld block(s) from %u\n", nm, since);
    }

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
