/* koinu.dog - choosing between the chains two peers serve
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Two socketpair peers, each preloaded with its own fork of a common base. The
 * headers are mined for real at regtest difficulty, so the validator pool has
 * something to check rather than being switched off for the test: a comparison
 * between chains that were never checked would be a comparison between claims.
 *
 * The case that matters is the short chain winning. A wallet that took the
 * longest chain would take the wrong one here. */

#include "chainsel.h"
#include "sync.h"
#include "peer.h"
#include "headers.h"
#include "proto.h"
#include "msg.h"
#include "pow.h"
#include "scrypt.h"
#include "chainparams.h"
#include "hex.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define EASY 0x207fffffu          /* regtest's own difficulty */
#define HARD 0x20550000u          /* target ~2/3 of it, so ~1.5x the work */

/* Fill in a header on (prev) at (bits) and find a nonce whose scrypt hash is
   under the target. At these difficulties that is a handful of tries. */
/* Regtest's genesis timestamp. A header has to be newer than the median of the
   eleven before it, so the harness stamps time from the seed: every chain built
   here walks its seeds upward, and a fixed timestamp on every header, which is
   what this used to do, is a chain no node would accept. */
#define BASE_TIME 1296688602u

static int mine(uint8_t raw[80], const uint8_t prev[32], uint32_t bits, uint32_t seed)
{
    memset(raw, 0, 80);
    raw[0] = 1;                                    /* version */
    memcpy(raw + 4, prev, 32);
    raw[36 + 0] = (uint8_t)seed;                   /* a merkle root, unique per header */
    raw[36 + 1] = (uint8_t)(seed >> 8);
    uint32_t when = BASE_TIME + 600u + seed * 60u;
    raw[68] = (uint8_t)when; raw[69] = (uint8_t)(when >> 8);
    raw[70] = (uint8_t)(when >> 16); raw[71] = (uint8_t)(when >> 24);
    for (int i = 0; i < 4; i++) raw[72 + i] = (uint8_t)(bits >> (8 * i));

    for (uint32_t nonce = 0; nonce < 100000; nonce++) {
        for (int i = 0; i < 4; i++) raw[76 + i] = (uint8_t)(nonce >> (8 * i));
        uint8_t h[32];
        if (!kw_scrypt_pow(raw, h, NULL)) return 0;
        if (kw_pow_check(h, bits)) return 1;
    }
    return 0;
}

/* A header on (prev) whose nonce does not satisfy its own target. Searched for
   rather than made by flipping a bit of a good one: regtest's target is most of
   the 256-bit range, so a flipped nonce usually still passes and the test would
   be asserting nothing. */
static int mine_bad(uint8_t raw[80], const uint8_t prev[32], uint32_t bits, uint32_t seed)
{
    memset(raw, 0, 80);
    raw[0] = 1;
    memcpy(raw + 4, prev, 32);
    raw[36 + 0] = (uint8_t)seed;
    raw[36 + 1] = (uint8_t)(seed >> 8);
    uint32_t when = BASE_TIME + 600u + seed * 60u;
    raw[68] = (uint8_t)when; raw[69] = (uint8_t)(when >> 8);
    raw[70] = (uint8_t)(when >> 16); raw[71] = (uint8_t)(when >> 24);
    for (int i = 0; i < 4; i++) raw[72 + i] = (uint8_t)(bits >> (8 * i));

    for (uint32_t nonce = 0; nonce < 100000; nonce++) {
        for (int i = 0; i < 4; i++) raw[76 + i] = (uint8_t)(nonce >> (8 * i));
        uint8_t h[32];
        if (!kw_scrypt_pow(raw, h, NULL)) return 0;
        if (!kw_pow_check(h, bits)) return 1;
    }
    return 0;
}

/* A peer that answers (nfull) getheaders rounds with its whole chain and every
   round after that with nothing, which is what a node with one chain does. Two
   full answers is the normal cost of a candidate: one to find where the fork is,
   one for the sync that follows it. */
static int fake_peer(kw_peer *p, const kw_chainparams *cp,
                     uint8_t (*raws)[80], int n, int nfull)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return 0;
    struct timeval tv = { 5, 0 };
    setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    uint8_t frame[8192];
    for (int r = 0; r < nfull; r++) {
        uint8_t payload[4096];
        size_t pn = 0;
        payload[pn++] = (uint8_t)n;
        for (int i = 0; i < n; i++) { memcpy(payload + pn, raws[i], 80); pn += 80; payload[pn++] = 0x00; }
        size_t fn = kw_msg_serialize(cp->magic, "headers", payload, pn, frame, sizeof frame);
        if (!fn || write(sv[1], frame, fn) != (ssize_t)fn) { close(sv[0]); close(sv[1]); return 0; }
    }
    for (int r = 0; r < 2; r++) {                  /* and then nothing, twice over */
        uint8_t empty = 0x00;
        size_t fn = kw_msg_serialize(cp->magic, "headers", &empty, 1, frame, sizeof frame);
        if (!fn || write(sv[1], frame, fn) != (ssize_t)fn) { close(sv[0]); close(sv[1]); return 0; }
    }
    kw_peer_from_fd(p, cp->magic, sv[0]);
    p->cp = cp;
    return 1;
}

static int build_chain(uint8_t (*raws)[80], int n, const uint8_t base[32], uint32_t bits, uint32_t tag)
{
    uint8_t prev[32];
    memcpy(prev, base, 32);
    for (int i = 0; i < n; i++) {
        if (!mine(raws[i], prev, bits, tag + (uint32_t)i)) return 0;
        kw_block_header h;
        if (!kw_block_header_parse(raws[i], 80, &h)) return 0;
        memcpy(prev, h.hash, 32);
    }
    return 1;
}

int main(void)
{
    kw_chainparams cp = KW_DOGE_REGTEST;
    cp.checkpoints = NULL; cp.ncheckpoints = 0;    /* nothing pinned: work decides */

    /* the block both forks build on */
    uint8_t base_raw[80];
    uint8_t zero[32];
    memset(zero, 0, 32);
    if (!mine(base_raw, zero, EASY, 1)) { fprintf(stderr, "FAIL: could not mine the base\n"); return 1; }
    kw_block_header base;
    kw_block_header_parse(base_raw, 80, &base);

    /* four easy headers against three harder ones: 4 vs 4.5 units of work */
    uint8_t longer[4][80], shorter[3][80];
    if (!build_chain(longer, 4, base.hash, EASY, 100) ||
        !build_chain(shorter, 3, base.hash, HARD, 200))
        { fprintf(stderr, "FAIL: could not mine the forks\n"); return 1; }

    /* the premise: fewer headers, more work */
    {
        kw_u256 wl, ws, w;
        kw_u256_zero(&wl); kw_u256_zero(&ws);
        for (int i = 0; i < 4; i++) { kw_bits_work(EASY, &w); kw_u256_add(&wl, &w); }
        for (int i = 0; i < 3; i++) { kw_bits_work(HARD, &w); kw_u256_add(&ws, &w); }
        if (kw_u256_cmp(&ws, &wl) <= 0)
            { fprintf(stderr, "FAIL: the short fork is not the heavier one\n"); return 1; }
    }

    /* the long fork first, so a winner cannot come from ordering */
    {
        kw_headerstore s;
        kw_headerstore_init(&s);
        if (!kw_headerstore_append(&s, &base)) { fprintf(stderr, "FAIL: seed\n"); return 1; }

        kw_peer a, b;
        if (!fake_peer(&a, &cp, longer, 4, 2) || !fake_peer(&b, &cp, shorter, 3, 2))
            { fprintf(stderr, "FAIL: could not build the peers\n"); return 1; }
        kw_peer *const peers[2] = { &a, &b };

        kw_chainsel_result r;
        long n = kw_sync_headers_best(peers, 2, &s, &cp, 1, &r);
        kw_peer_close(&a); kw_peer_close(&b);

        if (n != 3) { fprintf(stderr, "FAIL: appended %ld, want the 3 of the heavier fork\n", n); return 1; }
        if (r.winner != 1) { fprintf(stderr, "FAIL: peer %d won, want 1\n", r.winner); return 1; }
        if (r.ncandidates != 2) { fprintf(stderr, "FAIL: %d candidates, want 2\n", r.ncandidates); return 1; }
        if (r.fork_height != 1) { fprintf(stderr, "FAIL: forked at %u, want 1\n", r.fork_height); return 1; }
        if (s.count != 4) { fprintf(stderr, "FAIL: store holds %zu, want base plus 3\n", s.count); return 1; }
        kw_block_header want;
        kw_block_header_parse(shorter[2], 80, &want);
        if (memcmp(kw_headerstore_tip(&s)->hash, want.hash, 32) != 0)
            { fprintf(stderr, "FAIL: the tip is not the heavier fork's\n"); return 1; }
        kw_headerstore_free(&s);
    }

    /* a chain already held is a candidate: the lighter fork must not replace it */
    {
        kw_headerstore s;
        kw_headerstore_init(&s);
        kw_headerstore_append(&s, &base);
        for (int i = 0; i < 3; i++) {
            kw_block_header h;
            kw_block_header_parse(shorter[i], 80, &h);
            kw_headerstore_append(&s, &h);
        }

        kw_peer a;
        if (!fake_peer(&a, &cp, longer, 4, 2)) { fprintf(stderr, "FAIL: peer\n"); return 1; }
        kw_peer *const peers[2] = { &a, NULL };

        kw_chainsel_result r;
        long n = kw_sync_headers_best(peers, 2, &s, &cp, 1, &r);
        kw_peer_close(&a);

        if (n != 0) { fprintf(stderr, "FAIL: appended %ld, want the cache kept\n", n); return 1; }
        if (r.winner != -1) { fprintf(stderr, "FAIL: peer %d beat the cache\n", r.winner); return 1; }
        if (s.count != 4) { fprintf(stderr, "FAIL: store holds %zu after keeping its own\n", s.count); return 1; }
        kw_block_header want;
        kw_block_header_parse(shorter[2], 80, &want);
        if (memcmp(kw_headerstore_tip(&s)->hash, want.hash, 32) != 0)
            { fprintf(stderr, "FAIL: the cached tip was replaced by a lighter chain\n"); return 1; }
        kw_headerstore_free(&s);
    }

    /* a fork whose work is real but whose header is not: one bad nonce and the
       chain is dropped however heavy it claims to be */
    {
        uint8_t faked[5][80];
        if (!build_chain(faked, 4, base.hash, EASY, 300))
            { fprintf(stderr, "FAIL: could not mine the fifth fork\n"); return 1; }
        kw_block_header fourth;
        kw_block_header_parse(faked[3], 80, &fourth);
        if (!mine_bad(faked[4], fourth.hash, EASY, 399))
            { fprintf(stderr, "FAIL: could not find a header that fails its target\n"); return 1; }

        kw_headerstore s;
        kw_headerstore_init(&s);
        kw_headerstore_append(&s, &base);

        kw_peer a, b;
        if (!fake_peer(&a, &cp, faked, 5, 2) || !fake_peer(&b, &cp, shorter, 3, 2))
            { fprintf(stderr, "FAIL: peers\n"); return 1; }
        kw_peer *const peers[2] = { &a, &b };

        kw_chainsel_result r;
        long n = kw_sync_headers_best(peers, 2, &s, &cp, 1, &r);
        kw_peer_close(&a); kw_peer_close(&b);

        if (r.winner != 1)
            { fprintf(stderr, "FAIL: peer %d won with a header that fails its own target\n", r.winner); return 1; }
        if (n != 3) { fprintf(stderr, "FAIL: appended %ld after dropping the bad peer\n", n); return 1; }
        if (r.ncandidates != 1) { fprintf(stderr, "FAIL: %d candidates, want 1\n", r.ncandidates); return 1; }
        kw_headerstore_free(&s);
    }

    /* One peer, and its chain fails the work check: the store has to come back to
       what it held. The appends happen before the pool's verdict, so a failure
       left them behind, and kwd, which keeps its store for the life of the
       process, then synced onto them and answered from headers nobody checked. */
    {
        uint8_t faked[5][80];
        if (!build_chain(faked, 4, base.hash, EASY, 700))
            { fprintf(stderr, "FAIL: could not mine the single-peer fork\n"); return 1; }
        kw_block_header fourth;
        kw_block_header_parse(faked[3], 80, &fourth);
        if (!mine_bad(faked[4], fourth.hash, EASY, 799))
            { fprintf(stderr, "FAIL: could not find a failing header\n"); return 1; }

        kw_headerstore s;
        kw_headerstore_init(&s);
        kw_headerstore_append(&s, &base);

        kw_peer a;
        if (!fake_peer(&a, &cp, faked, 5, 2)) { fprintf(stderr, "FAIL: peer\n"); return 1; }
        kw_peer *const one[1] = { &a };
        kw_chainsel_result r;
        long n = kw_sync_headers_best(one, 1, &s, &cp, 1, &r);
        kw_peer_close(&a);

        if (n >= 0) { fprintf(stderr, "FAIL: a failing chain synced from one peer\n"); return 1; }
        if (s.count != 1) {
            fprintf(stderr, "FAIL: %zu headers left in the store after the failure, want 1\n",
                    s.count);
            return 1;
        }
        kw_headerstore_free(&s);
    }

    /* The tail bound has to count what the comparison will hold. With an empty
       store the cached tail is zero, so it never fired while each peer served
       the whole chain and each candidate was held and hashed in full. A peer's
       advertised height says how far that is before anything is fetched. */
    {
        uint8_t chain[3][80];
        if (!build_chain(chain, 3, base.hash, EASY, 900))
            { fprintf(stderr, "FAIL: could not mine the span fork\n"); return 1; }

        kw_headerstore s;
        kw_headerstore_init(&s);
        kw_headerstore_append(&s, &base);

        kw_peer a, b;
        /* one full round each: the fallback syncs straight from peer 0 without
           the fork-point round the comparison would have spent first */
        if (!fake_peer(&a, &cp, chain, 3, 1) || !fake_peer(&b, &cp, chain, 3, 1))
            { fprintf(stderr, "FAIL: peers\n"); return 1; }
        a.peer_height = 400000;                  /* more than the bound allows */
        b.peer_height = 400000;
        kw_peer *const peers[2] = { &a, &b };

        kw_chainsel_result r;
        long n = kw_sync_headers_best(peers, 2, &s, &cp, 1, &r);
        kw_peer_close(&a); kw_peer_close(&b);

        if (n != 3) { fprintf(stderr, "FAIL: appended %ld with one peer, want 3\n", n); return 1; }
        if (r.ncandidates != 1) {
            fprintf(stderr, "FAIL: %d candidates weighed past the bound, want 1\n",
                    r.ncandidates);
            return 1;
        }
        kw_headerstore_free(&s);
    }

    /* And one peer alone must not put the comparison past the bound. The span was
       taken from the highest advertised height, so a peer claiming 2^31-1 in its
       version message collapsed the weighing to peers[0], which may be that peer:
       a single lying peer could switch off the comparison the threat model rests
       on. The bound is a median now, so a claim nobody else makes does not move
       it. */
    {
        uint8_t liar[3][80];
        if (!build_chain(liar, 3, base.hash, EASY, 950))
            { fprintf(stderr, "FAIL: could not mine the liar's fork\n"); return 1; }

        kw_headerstore s;
        kw_headerstore_init(&s);
        kw_headerstore_append(&s, &base);

        kw_peer a, b;
        if (!fake_peer(&a, &cp, liar, 3, 2) || !fake_peer(&b, &cp, liar, 3, 2))
            { fprintf(stderr, "FAIL: peers\n"); return 1; }
        a.peer_height = 2147483647;              /* the liar */
        b.peer_height = 4;
        kw_peer *const peers[2] = { &a, &b };

        kw_chainsel_result r;
        long n = kw_sync_headers_best(peers, 2, &s, &cp, 1, &r);
        kw_peer_close(&a); kw_peer_close(&b);

        if (n < 0) { fprintf(stderr, "FAIL: the sync failed with a lying peer\n"); return 1; }
        if (r.ncandidates != 2) {
            fprintf(stderr, "FAIL: one peer's claimed height left %d candidate(s), want 2\n",
                    r.ncandidates);
            return 1;
        }
        kw_headerstore_free(&s);
    }

    /* One peer, and the chain it serves replaces the cached tip. The locator used
       to carry only that tip, so after a reorg the peer answered from genesis,
       the first header linked to nothing held, and the sync failed: with one
       --node and --headers, every command stayed broken until the cache was
       deleted by hand, and kwd failed every request and again at restart. */
    {
        uint8_t mine[2][80], theirs[3][80];
        if (!build_chain(mine, 2, base.hash, EASY, 1100) ||
            !build_chain(theirs, 3, base.hash, EASY, 1200))
            { fprintf(stderr, "FAIL: could not mine the reorg forks\n"); return 1; }

        kw_headerstore s;
        kw_headerstore_init(&s);
        kw_headerstore_append(&s, &base);
        for (int i = 0; i < 2; i++) {
            kw_block_header h;
            kw_block_header_parse(mine[i], 80, &h);
            kw_headerstore_append(&s, &h);
        }
        if (s.count != 3) { fprintf(stderr, "FAIL: cache setup\n"); return 1; }

        kw_peer a;
        if (!fake_peer(&a, &cp, theirs, 3, 1)) { fprintf(stderr, "FAIL: peer\n"); return 1; }
        kw_peer *const one[1] = { &a };
        kw_chainsel_result r;
        long n = kw_sync_headers_best(one, 1, &s, &cp, 1, &r);
        kw_peer_close(&a);

        if (n < 0) { fprintf(stderr, "FAIL: a one-peer reorg failed the sync\n"); return 1; }
        if (s.count != 4) {
            fprintf(stderr, "FAIL: store holds %zu after the reorg, want 4\n", s.count);
            return 1;
        }
        kw_block_header want;
        kw_block_header_parse(theirs[2], 80, &want);
        if (memcmp(s.h[s.count - 1].hash, want.hash, 32) != 0) {
            fprintf(stderr, "FAIL: the tip is not the peer's\n"); return 1;
        }
        kw_headerstore_free(&s);
    }

    /* An empty store, which is what every first run has: no cache, or a command
       like sweep that never keeps one. The peer's first header builds on genesis,
       and genesis is not a header the store ever holds, so resolving its parent
       has to know about the chain's own starting point rather than looking for it
       among the headers. Getting this wrong drops every peer and syncs nothing. */
    {
        uint8_t gen[32], disp[32];
        if (!kw_hex_decode(cp.genesis, 64, disp, 32))
            { fprintf(stderr, "FAIL: genesis hex\n"); return 1; }
        for (int i = 0; i < 32; i++) gen[i] = disp[31 - i];

        uint8_t fresh[3][80];
        if (!build_chain(fresh, 3, gen, EASY, 700))
            { fprintf(stderr, "FAIL: could not mine a chain on genesis\n"); return 1; }

        kw_headerstore s;
        kw_headerstore_init(&s);                   /* nothing cached at all */

        kw_peer a, b;
        if (!fake_peer(&a, &cp, fresh, 3, 2) || !fake_peer(&b, &cp, fresh, 3, 2))
            { fprintf(stderr, "FAIL: peers\n"); return 1; }
        kw_peer *const peers[2] = { &a, &b };

        kw_chainsel_result r;
        long n = kw_sync_headers_best(peers, 2, &s, &cp, 1, &r);
        kw_peer_close(&a); kw_peer_close(&b);

        if (n != 3) { fprintf(stderr, "FAIL: a first run appended %ld, want 3\n", n); return 1; }
        if (s.count != 3) { fprintf(stderr, "FAIL: store holds %zu after a first run\n", s.count); return 1; }
        if (r.ncandidates != 2) { fprintf(stderr, "FAIL: %d candidates from an empty store\n", r.ncandidates); return 1; }
        if (r.fork_height != 0) { fprintf(stderr, "FAIL: forked at %u, want genesis\n", r.fork_height); return 1; }
        kw_block_header want;
        kw_block_header_parse(fresh[2], 80, &want);
        if (memcmp(kw_headerstore_tip(&s)->hash, want.hash, 32) != 0)
            { fprintf(stderr, "FAIL: the tip is not what the peers served\n"); return 1; }
        kw_headerstore_free(&s);
    }

    printf("chainsel ok: the heavier of two forks wins over the longer one, the cached\n"
           "  chain is a candidate, a fork with a header that fails its target is dropped,\n  one peer failing leaves nothing behind, a span past the bound falls back\n  to one peer while one peer's claimed height does not, a one-peer reorg is\n  followed rather than wedging the cache,\n"
           "  and a first run with no cache syncs from genesis\n");
    return 0;
}
