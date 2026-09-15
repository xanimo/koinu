/* koinu.dog - choosing between the chains peers serve
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "chainsel.h"
#include "sync.h"
#include "hex.h"
#include "msg.h"
#include "pow.h"
#include "powq.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* How many headers above the newest anchor this is willing to weigh. Each
   candidate holds the contested tail, so this is what bounds the memory. A
   release whose anchors are this far behind the chain should be updated rather
   than have every peer's fork buffered. */
#define KW_CHAINSEL_MAX_TAIL 200000

/* The height in (s) whose hash is (h), or 0. Searched from the tip, which is
   where a fork point almost always is. */
static uint32_t height_of(const kw_headerstore *s, const uint8_t h[32])
{
    for (size_t i = s->count; i-- > 0; )
        if (memcmp(s->h[i].hash, h, 32) == 0) return (uint32_t)(i + 1);
    return 0;
}

/* The newest anchor at or below (s)'s tip, or 0 when there is none. Below this
   height a compiled-in hash names the chain, so nothing here may roll back past
   it and no fork below it is worth weighing. */
static uint32_t anchor_floor(const kw_headerstore *s, const kw_chainparams *cp)
{
    uint32_t floor = 0;
    for (size_t i = 0; i < cp->ncheckpoints; i++) {
        uint32_t h = cp->checkpoints[i].height;
        if (h && h <= s->count && h > floor) floor = h;
    }
    return floor;
}

/* Put (s) back to (floor) plus (tail), which is what it held before a candidate
   rolled it back. Returns 1, or 0 if a header will not re-link, which cannot
   happen for a tail this code saved and means the store is no longer usable. */
static int restore(kw_headerstore *s, uint32_t floor,
                   const kw_block_header *tail, size_t ntail)
{
    kw_headerstore_truncate(s, floor);
    for (size_t i = 0; i < ntail; i++)
        if (!kw_headerstore_append(s, &tail[i])) return 0;
    return 1;
}

/* Ask (p) where its chain leaves ours. Sends a locator and reads one headers
   message: the height of the first returned header's parent is the fork point.
   Returns it, or 0 when the peer has nothing after our tip, or -1 on a wire
   error or a parent we have never heard of. */
static long fork_point(kw_peer *p, const kw_headerstore *s, const kw_chainparams *cp)
{
    uint8_t loc[KW_SYNC_LOCATOR_MAX][32];
    size_t nloc = kw_sync_locator(s, cp, loc, KW_SYNC_LOCATOR_MAX);
    if (!nloc) return -1;

    uint8_t body[16 + KW_SYNC_LOCATOR_MAX * 32 + 32];
    size_t bn = kw_msg_getheaders_build(KW_PROTOCOL_VERSION, loc, nloc, NULL,
                                        body, sizeof body);
    if (!bn || !kw_peer_send(p, "getheaders", body, bn)) return -1;

    char cmd[13]; const uint8_t *pl = NULL; size_t pn = 0;
    int got = 0;
    while (kw_peer_recv(p, cmd, &pl, &pn) == 1) {
        if (!strcmp(cmd, "headers")) { got = 1; break; }
        if (!strcmp(cmd, "ping")) kw_peer_send(p, "pong", pl, pn);
    }
    if (!got) return -1;

    /* The whole message has to be parsed to read the first header: the parser
       refuses a batch that exceeds the cap rather than filling what fits. */
    kw_block_header *batch = (kw_block_header *)malloc(KW_MAX_HEADERS * sizeof *batch);
    if (!batch) return -1;
    size_t nout = 0;
    if (kw_msg_headers_parse(pl, pn, batch, KW_MAX_HEADERS, &nout) != 1) { free(batch); return -1; }
    if (nout == 0) { free(batch); return 0; }    /* nothing after our tip */

    uint8_t prev[32];
    memcpy(prev, kw_block_header_prev(&batch[0]), 32);
    free(batch);
    uint32_t at = height_of(s, prev);
    if (!at) return -1;                          /* builds on a block we do not have */
    return (long)at;
}

long kw_sync_headers_best(kw_peer *const *peers, int npeers,
                          kw_headerstore *s, const kw_chainparams *cp,
                          uint32_t pow_from, kw_chainsel_result *out)
{
    kw_chainsel_result r;
    memset(&r, 0, sizeof r);
    r.winner = -1;
    r.npeers = npeers;
    if (out) *out = r;
    if (!peers || npeers < 1 || !s || !cp) return -1;

    /* One peer is the old behaviour: there is nothing to compare, so do not
       pretend to. The caller says so; this just does the sync. */
    if (npeers == 1) {
        kw_powq *q = kw_powq_start(0, 4096);
        if (!q) return -1;
        r.threads = kw_powq_threads(q);
        long n = kw_sync_headers_checked(peers[0], s, cp, q, pow_from);
        uint64_t checked = 0;
        int ok = kw_powq_finish(q, &checked, &r.bad_height);
        r.pow_checked += checked;
        if (n < 0 || !ok) { if (out) *out = r; return -1; }
        r.ncandidates = 1; r.winner = 0; r.appended = n;
        r.fork_height = (uint32_t)s->count - (uint32_t)n;
        if (out) *out = r;
        return n;
    }

    uint32_t floor = anchor_floor(s, cp);
    size_t ntail = s->count - floor;
    if (ntail > KW_CHAINSEL_MAX_TAIL) {
        fprintf(stderr, "kw: %zu headers above the newest anchor, too many to weigh "
                        "several peers' chains; using one\n", ntail);
        kw_peer *const one[1] = { peers[0] };
        return kw_sync_headers_best(one, 1, s, cp, pow_from, out);
    }

    /* The chain already held is the first candidate: a peer has to beat the cache,
       not merely differ from it. Its tail is saved because weighing a peer's chain
       means rolling back to the fork and the store has to come back. */
    kw_block_header *save = NULL;
    if (ntail) {
        save = (kw_block_header *)malloc(ntail * sizeof *save);
        if (!save) return -1;
        memcpy(save, s->h + floor, ntail * sizeof *save);
    }

    kw_u256 best_work;
    kw_u256_zero(&best_work);
    if (!kw_sync_chainwork(s, floor, (uint32_t)s->count, &best_work)) { free(save); return -1; }

    kw_block_header *best = NULL;
    size_t nbest = ntail;
    uint32_t best_fork = floor;
    int winner = -1;

    for (int i = 0; i < npeers; i++) {
        if (!peers[i]) continue;
        if (!restore(s, floor, save, ntail)) { free(save); free(best); return -1; }

        long at = fork_point(peers[i], s, cp);
        if (at < 0) {
            if (kw_net_verbose) fprintf(stderr, "[chain] peer %d served nothing usable\n", i);
            continue;
        }
        if (at == 0) {                            /* agrees with our tip */
            r.ncandidates++;
            continue;
        }
        if ((uint32_t)at < floor) {
            /* A fork below an anchor contradicts a hash compiled into the release,
               which no amount of work outweighs. */
            fprintf(stderr, "kw: a peer's chain forks at %ld, below the %u this release "
                            "pins; ignoring it\n", at, floor);
            continue;
        }

        kw_headerstore_truncate(s, (size_t)at);
        kw_powq *q = kw_powq_start(0, 4096);
        if (!q) { free(save); free(best); return -1; }
        r.threads = kw_powq_threads(q);
        long n = kw_sync_headers_checked(peers[i], s, cp, q, pow_from);
        uint64_t checked = 0;
        uint32_t bad = 0;
        int powok = kw_powq_finish(q, &checked, &bad);
        r.pow_checked += checked;
        if (n < 0 || !powok) {
            /* Its own pool, so one peer's bad header does not condemn another's
               chain. Recorded and dropped. */
            if (!powok) r.bad_height = bad;
            if (kw_net_verbose)
                fprintf(stderr, "[chain] peer %d dropped%s\n", i,
                        powok ? "" : ": a header does not prove its work");
            continue;
        }

        r.ncandidates++;
        kw_u256 w;
        kw_u256_zero(&w);
        if (!kw_sync_chainwork(s, floor, (uint32_t)s->count, &w)) continue;
        if (kw_u256_cmp(&w, &best_work) <= 0) continue;   /* ties keep what we had */

        size_t nn = s->count - floor;
        kw_block_header *keep = (kw_block_header *)malloc(nn ? nn * sizeof *keep : 1);
        if (!keep) { free(save); free(best); return -1; }
        memcpy(keep, s->h + floor, nn * sizeof *keep);
        free(best);
        best = keep; nbest = nn; best_work = w; best_fork = (uint32_t)at; winner = i;
    }

    /* Whatever won, the store ends up holding it. */
    const kw_block_header *apply = best ? best : save;
    size_t napply = best ? nbest : ntail;
    if (!restore(s, floor, apply, napply)) { free(save); free(best); return -1; }

    r.winner = winner;
    r.fork_height = winner < 0 ? (uint32_t)s->count : best_fork;
    r.appended = winner < 0 ? 0 : (long)(s->count - best_fork);
    if (out) *out = r;

    free(save);
    free(best);
    if (!r.ncandidates) return -1;
    return r.appended;
}
