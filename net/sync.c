/* koinu.dog - header chain sync driver
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "sync.h"
#include "pow.h"
#include "msg.h"
#include "hex.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int kw_net_verbose = 0;

/* The nBits and timestamp of (height), from the store, or from chainparams when it
   is genesis, which a store never holds. */
static int header_at(const kw_headerstore *s, const kw_chainparams *cp,
                     uint32_t height, uint32_t *bits, uint32_t *time)
{
    if (height == 0) {
        *bits = cp->genesis_bits;
        *time = cp->genesis_time;
        return cp->genesis_time != 0;
    }
    if (height > s->count) return 0;
    const uint8_t *raw = s->h[height - 1].raw;
    *bits = kw_header_bits(raw);
    *time = kw_header_time(raw);
    return 1;
}

int kw_sync_bits_ok(const kw_headerstore *s, const kw_chainparams *cp,
                    uint32_t height, uint32_t bits)
{
    /* Only mainnet's rules are written. Testnet and regtest allow minimum-difficulty
       blocks, which needs a walk this does not do, so they are not checked at all
       rather than checked wrongly. */
    if (!s || !cp || cp != &KW_DOGE_MAINNET) return 1;
    if (height == 0) return 1;

    uint32_t last_bits, last_time, first_time = 0, first_bits;
    if (!header_at(s, cp, height - 1, &last_bits, &last_time)) return 0;

    uint32_t first_height;
    if (kw_pow_retargets(&KW_POW_MAIN, height, &first_height) &&
        !header_at(s, cp, first_height, &first_bits, &first_time)) return 0;

    return bits == kw_pow_next_bits(&KW_POW_MAIN, height, last_bits, last_time, first_time);
}

/* Submitting to the pool as headers are parsed, counting heights from the store's
   current tip. A refusal here abandons the parse: the queue only refuses once a
   header has already failed, and there is no point downloading the rest. */
struct feed { kw_powq *q; uint32_t from, height, stopped; };

static int on_header(void *ctx, const kw_block_header *h, const uint8_t *aux, size_t auxlen)
{
    struct feed *f = (struct feed *)ctx;
    uint32_t at = f->height++;
    if (at < f->from) return 1;
    if (!kw_powq_submit(f->q, at, h->raw, aux, auxlen)) { f->stopped = 1; return 0; }
    return 1;
}

long kw_sync_headers(kw_peer *p, kw_headerstore *s, const kw_chainparams *cp)
{
    return kw_sync_headers_checked(p, s, cp, NULL, 0);
}

long kw_sync_headers_checked(kw_peer *p, kw_headerstore *s, const kw_chainparams *cp,
                             kw_powq *q, uint32_t from_height)
{
    /* genesis hash in internal order, for the initial locator and link check */
    uint8_t genesis[32], disp[32];
    if (!cp || !kw_hex_decode(cp->genesis, 64, disp, 32)) return -1;
    for (int i = 0; i < 32; i++) genesis[i] = disp[31 - i];

    kw_block_header *batch = (kw_block_header *)malloc(KW_MAX_HEADERS * sizeof *batch);
    if (!batch) return -1;

    long total = 0;
    for (;;) {
        const kw_block_header *tip = kw_headerstore_tip(s);
        uint8_t loc[32];
        if (tip) memcpy(loc, tip->hash, 32);
        else     memcpy(loc, genesis, 32);

        uint8_t body[128];
        size_t bn = kw_msg_getheaders_build(KW_PROTOCOL_VERSION,
                                            (const uint8_t (*)[32])loc, 1, NULL,
                                            body, sizeof body);
        if (!bn || !kw_peer_send(p, "getheaders", body, bn)) { free(batch); return -1; }

        /* read past anything that is not a headers message, answering pings */
        char cmd[13]; const uint8_t *pl = NULL; size_t pn = 0;
        int got = 0, r;
        while ((r = kw_peer_recv(p, cmd, &pl, &pn)) == 1) {
            if (!strcmp(cmd, "headers")) { got = 1; break; }
            if (!strcmp(cmd, "ping")) kw_peer_send(p, "pong", pl, pn);
        }
        if (!got) { free(batch); return -1; }

        size_t nout = 0;
        /* the height the first header of this message will take, so the callback can
           tell what is above the anchor and what is already pinned by one */
        struct feed f = { q, from_height, (uint32_t)s->count + 1, 0 };
        if (kw_msg_headers_parse_cb(pl, pn, batch, KW_MAX_HEADERS, &nout,
                                    q ? on_header : NULL, &f) != 1) { free(batch); return -1; }
        if (f.stopped) { free(batch); return -1; }
        if (nout == 0) break;                    /* peer has nothing after our tip */

        /* seeding from empty: the first header must build on genesis */
        if (!kw_headerstore_tip(s) &&
            memcmp(kw_block_header_prev(&batch[0]), genesis, 32) != 0) { free(batch); return -1; }

        for (size_t i = 0; i < nout; i++) {
            /* The difficulty a header claims has to be the one the chain demands of
               it, or work proves only that energy went somewhere. Checked before the
               append, so the store never holds a header the rule refuses, and with
               the store still ending at the previous height. */
            uint32_t height = (uint32_t)s->count + 1;
            if (!kw_sync_bits_ok(s, cp, height, kw_header_bits(batch[i].raw))) {
                if (kw_net_verbose)
                    fprintf(stderr, "[headers] %u carries the wrong difficulty\n", height);
                free(batch);
                return -1;
            }
            if (!kw_headerstore_append(s, &batch[i])) { free(batch); return -1; }
            total++;
        }
        if (kw_net_verbose) fprintf(stderr, "[headers] %ld synced\n", total);
    }

    free(batch);
    return total;
}
