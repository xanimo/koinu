/* koinu.dog - header chain sync driver
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "sync.h"
#include "sha2.h"
#include "pow.h"
#include "auxpow.h"
#include "msg.h"
#include "hex.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

/* display hex to internal order */
static int unhex_rev(const char *hex, uint8_t out[32])
{
    uint8_t d[32];
    if (!kw_hex_decode(hex, 64, d, 32)) return 0;
    for (int i = 0; i < 32; i++) out[i] = d[31 - i];
    return 1;
}

/* the first anchor at or above (height), so the walk can advance one cursor rather
   than search the table per header */
static size_t cp_from(const kw_chainparams *cp, uint32_t height)
{
    size_t i = 0;
    while (i < cp->ncheckpoints && cp->checkpoints[i].height < height) i++;
    return i;
}

size_t kw_sync_locator(const kw_headerstore *s, const kw_chainparams *cp,
                       uint8_t (*out)[32], size_t max)
{
    if (!s || !cp || !out || !max) return 0;

    size_t n = 0;
    /* heights, not indices: height h sits at s->h[h - 1] */
    uint32_t h = (uint32_t)s->count;
    uint32_t step = 1;
    for (int taken = 0; h >= 1 && n < max; taken++) {
        memcpy(out[n++], s->h[h - 1].hash, 32);
        if (taken >= 9) step *= 2;                  /* ten singles, then doubling */
        if (h <= step) break;
        h -= step;
    }

    /* The newest anchor at or below the tip, so a peer whose fork is deep still
       gets one hash it must recognise, and genesis, which every peer knows. */
    for (size_t i = cp->ncheckpoints; i-- > 0 && n < max; ) {
        uint32_t ch = cp->checkpoints[i].height;
        if (ch == 0 || ch > s->count) continue;
        if (!unhex_rev(cp->checkpoints[i].hash, out[n])) break;
        n++;
        break;
    }
    if (n < max) {
        uint8_t disp[32];
        if (kw_hex_decode(cp->genesis, 64, disp, 32)) {
            for (int i = 0; i < 32; i++) out[n][i] = disp[31 - i];
            n++;
        }
    }
    return n;
}

static long sync_since_ms(const struct timespec *t0)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return (now.tv_sec - t0->tv_sec) * 1000 + (now.tv_nsec - t0->tv_nsec) / 1000000;
}

int kw_sync_chainwork(const kw_headerstore *s, uint32_t from, uint32_t to,
                      kw_u256 *out)
{
    if (!s || !out || to < from || to > s->count) return 0;
    for (uint32_t h = from + 1; h <= to; h++) {
        kw_u256 w;
        if (!kw_bits_work(kw_header_bits(s->h[h - 1].raw), &w)) return 0;
        if (kw_u256_add(out, &w)) return 0;         /* wrapped: not a real chain */
    }
    return 1;
}

int kw_sync_version_ok(const kw_chainparams *cp, uint32_t height, uint32_t version)
{
    if (!cp) return 0;

    /* The version floors BIP66 and BIP65 brought in, which a node enforces on the
       header alone. The chain id and the auxpow flag sit above the base version,
       so the comparison is against the low byte. BIP34's floor was never
       enforced on dogecoin, and its coinbase-height rule needs the body. */
    uint32_t base = version & 0xff;
    if (cp->bip66_height && height >= cp->bip66_height && base < 3) return 0;
    if (cp->bip65_height && height >= cp->bip65_height && base < 4) return 0;

    if (cp->magic != KW_DOGE_MAINNET.magic) return 1;
    if (height < KW_AUXPOW_START_MAINNET) return 1;

    /* legacy is version 1, or 2, which carries no chain id */
    if (version == 1 || version == 2) return 0;
    return (int32_t)(version >> 16) == KW_AUXPOW_CHAIN_ID;
}

int kw_sync_time_ok(const kw_headerstore *s, const kw_chainparams *cp,
                    uint32_t height, uint32_t htime, int64_t now)
{
    if (!s || !cp) return 0;
    if (height == 0) return 1;
    if (now > 0 && (int64_t)htime > now + KW_SYNC_MAX_FUTURE) return 0;

    uint32_t t[KW_SYNC_MTP_SPAN];
    size_t n = 0;
    for (uint32_t h = height; h-- > 0 && n < KW_SYNC_MTP_SPAN; ) {
        uint32_t b, tt;
        if (!header_at(s, cp, h, &b, &tt)) break;
        t[n++] = tt;
        if (h == 0) break;
    }
    if (n == 0) return 1;                        /* nothing to compare against */

    for (size_t i = 1; i < n; i++) {             /* eleven elements, so insertion */
        uint32_t v = t[i];
        size_t j = i;
        while (j > 0 && t[j - 1] > v) { t[j] = t[j - 1]; j--; }
        t[j] = v;
    }
    return htime > t[n / 2];
}

int kw_sync_bits_ok(const kw_headerstore *s, const kw_chainparams *cp,
                    uint32_t height, uint32_t bits)
{
    if (!s || !cp) return 1;

    /* No target may be easier than the network's powLimit, which is Core's
       CheckProofOfWork and is the same rule on every network. Without it a
       testnet or regtest peer served headers at nbits 0x2100ffff with nonce 0,
       and testnet has no checkpoints to catch the chain afterwards. */
    kw_u256 target, limit;
    if (!kw_bits_target(bits, &target)) return 0;
    if (cp->pow_limit_bits && kw_bits_target(cp->pow_limit_bits, &limit) &&
        kw_u256_cmp(&target, &limit) > 0) return 0;

    /* Past that only mainnet's retarget rule is written. Testnet and regtest
       allow minimum-difficulty blocks, which needs a walk this does not do, so
       the derived value is not demanded of them rather than demanded wrongly. */
    if (cp->magic != KW_DOGE_MAINNET.magic) return 1;
    if (height == 0) return 1;

    uint32_t last_bits, last_time, first_time = 0, first_bits;
    if (!header_at(s, cp, height - 1, &last_bits, &last_time)) return 0;

    uint32_t first_height;
    if (kw_pow_retargets(&KW_POW_MAIN, height, &first_height) &&
        !header_at(s, cp, first_height, &first_bits, &first_time)) return 0;

    return bits == kw_pow_next_bits(&KW_POW_MAIN, height, last_bits, last_time, first_time);
}

int kw_sync_anchors_ok(const kw_headerstore *s, const kw_chainparams *cp,
                       uint32_t *bad_height)
{
    if (!s || !cp) return 0;
    uint32_t newest = 0;
    for (size_t i = 0; i < cp->ncheckpoints; i++) {
        uint32_t h = cp->checkpoints[i].height;
        if (h == 0 || h > s->count) continue;          /* genesis is not stored */
        /* Hashed here rather than compared against the record's stored hash. A
           KWH2 cache carries the hash beside the header and the load trusts it,
           so comparing a checkpoint against that compares the file with itself.
           A few dozen anchors cost nothing; hashing all six million on load is
           seven seconds, which is what the stored hash exists to avoid. */
        uint8_t want[32], got[32];
        kw_hash256(s->h[h - 1].raw, KW_HEADER_LEN, got);
        if (!unhex_rev(cp->checkpoints[i].hash, want) ||
            memcmp(want, got, 32) != 0) {
            if (bad_height) *bad_height = h;
            return 0;
        }
        if (h > newest) newest = h;
    }

    /* Above the newest anchor every record's hash is checked against its own
       header. The link check on load only ties each stored hash to the next
       record's prev, so a cache whose raw bytes were edited and whose stored
       hashes were left consistent passes it, and up here the raw is what the
       timestamp, retarget and work rules read: an edited nBits inflates the
       cached chain's work and wins the comparison against a peer serving the
       real one. Below the anchors nothing reads a raw header except this loop,
       since every other use asks a peer for the block at a hash and a forged
       hash has no block behind it.

       The span is bounded by the anchor spacing, so this is the part of the
       store where hashing is affordable: 60k records is 80ms without sha-ni,
       against seven seconds for all 6.36M, which is what the stored hash
       exists to avoid. */
    for (size_t h = newest + 1; h <= s->count; h++) {
        uint8_t got[32];
        kw_hash256(s->h[h - 1].raw, KW_HEADER_LEN, got);
        if (memcmp(got, s->h[h - 1].hash, 32) != 0) {
            if (bad_height) *bad_height = (uint32_t)h;
            return 0;
        }
    }
    return 1;
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

/* The first header's prev hash, straight out of a headers payload: the count
   varint, then an 80-byte header whose prev sits at offset 4. Read without
   parsing the message, because the fork point has to be known before a single
   header reaches the validator pool: the pool is fed during the parse, with the
   heights the headers are about to take, and those heights change if the store
   is rolled back afterwards. */
static int peek_first_prev(const uint8_t *pl, size_t pn, uint8_t out[32])
{
    if (pn < 1) return 0;
    size_t off = 0;
    uint8_t t = pl[off++];
    if (t >= 0xfd) {
        int k = t == 0xfd ? 2 : t == 0xfe ? 4 : 8;
        if (off + (size_t)k > pn) return 0;
        off += (size_t)k;
    }
    if (off + 36 > pn) return 0;
    memcpy(out, pl + off + 4, 32);
    return 1;
}

/* The newest anchor at or below the store's tip. A fork below one is not a fork
   this release will follow. */
static uint32_t anchor_floor(const kw_headerstore *s, const kw_chainparams *cp)
{
    uint32_t floor = 0;
    for (size_t i = 0; i < cp->ncheckpoints; i++) {
        uint32_t h = cp->checkpoints[i].height;
        if (h && h <= s->count && h > floor) floor = h;
    }
    return floor;
}

/* The height (prev) sits at in the store, 0 for genesis, or -1 when it is not a
   block this store holds at or above (floor). */
static long link_height(const kw_headerstore *s, const uint8_t prev[32],
                        const uint8_t genesis[32], uint32_t floor)
{
    if (memcmp(prev, genesis, 32) == 0) return 0;
    for (size_t h = s->count; h > 0; h--) {
        if (memcmp(s->h[h - 1].hash, prev, 32) == 0) return (long)h;
        if (h - 1 <= (size_t)floor) break;
    }
    return -1;
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

    /* set once the peer's chain forks below our tip: what we dropped, so it can
       go back when the replacement does not outweigh it */
    long fork_at = -1;
    kw_block_header *dropped = NULL;
    size_t ndropped = 0;
    kw_u256 dropped_work;
    kw_u256_zero(&dropped_work);

    /* Anchors are the only thing that says this is the chain rather than a chain. A
       peer can link to genesis, satisfy the retarget rule and carry no work at all:
       the early heights inherit genesis nBits, so three headers with a zero nonce
       parse, link and pass every other rule. Verified here rather than only in the
       parallel fill, which is not the default path. */
    size_t cpi = cp_from(cp, (uint32_t)s->count + 1);

    long total = 0;
    int stop = 0;                 /* a header the chain refuses: keep what came before */
    for (;;) {
        /* Read per batch. A sequential mainnet sync from genesis takes longer
           than the two-hour bound, so a single (now) taken at the start makes
           honest headers near the tip look stamped in the future, and the sync
           fails at its last batch every time. */
        const int64_t now = (int64_t)time(NULL);
        /* The full locator, not just the tip. After a reorg the peer does not
           have our tip on its chain, and a one-hash locator makes it answer from
           genesis: the first header then links to nothing we hold, the append
           refuses, and a single-peer cache stays wedged until it is deleted by
           hand. The back-off gives the peer a hash it still recognises. */
        uint8_t loc[KW_SYNC_LOCATOR_MAX][32];
        size_t nloc = kw_sync_locator(s, cp, loc, KW_SYNC_LOCATOR_MAX);
        if (!nloc) {
            memcpy(loc[0], genesis, 32);
            nloc = 1;
        }

        uint8_t body[16 + KW_SYNC_LOCATOR_MAX * 32 + 32];
        size_t bn = kw_msg_getheaders_build(KW_PROTOCOL_VERSION,
                                            (const uint8_t (*)[32])loc, nloc, NULL,
                                            body, sizeof body);
        if (!bn || !kw_peer_send(p, "getheaders", body, bn)) { goto fail; }

        /* Read past anything that is not a headers message, answering pings. The
           socket timeout stops a silent peer, but a peer that sends one
           well-formed message inside every timeout window would keep a sync alive
           forever without advancing it, so the detour is also bounded by count. */
        char cmd[13]; const uint8_t *pl = NULL; size_t pn = 0;
        int got = 0, r;
        int skipped = 0;
        /* and a deadline beside the count, since the count multiplies by whatever
           one recv may take rather than bounding the detour in time */
        struct timespec d0;
        clock_gettime(CLOCK_MONOTONIC, &d0);
        while ((r = kw_peer_recv(p, cmd, &pl, &pn)) == 1) {
            if (!strcmp(cmd, "headers")) { got = 1; break; }
            if (!strcmp(cmd, "ping")) kw_peer_send(p, "pong", pl, pn);
            if (sync_since_ms(&d0) > KW_PEER_EXCHANGE_SECONDS * 1000L) {
                if (kw_net_verbose)
                    fprintf(stderr, "[headers] peer spent %d seconds not answering\n",
                            KW_PEER_EXCHANGE_SECONDS);
                break;
            }
            if (++skipped > KW_SYNC_MAX_SKIP) {
                if (kw_net_verbose)
                    fprintf(stderr, "[headers] peer sent %d messages without headers\n", skipped);
                break;
            }
        }
        if (!got) { goto fail; }

        /* Where this batch attaches. A peer answering a locator can legitimately
           start below our tip, which is what a reorganisation looks like: drop
           what we hold above that point rather than refusing the batch. */
        uint8_t first_prev[32];
        /* An empty message means the peer has nothing after our tip and carries
           no header to attach, so the parse below ends the loop instead. */
        long at = peek_first_prev(pl, pn, first_prev)
                      ? link_height(s, first_prev, genesis, anchor_floor(s, cp))
                      : (long)s->count;
        if (at < 0) { goto fail; }      /* builds on nothing we hold */
        if ((size_t)at < s->count) {
            /* A reorganisation is only one if what replaces the tail is heavier.
               Dropping first and appending after would let a single peer shorten
               the chain for free, which is what the work comparison exists to
               stop, so the tail is kept until the replacement has earned it. */
            if (fork_at < 0) {
                ndropped = s->count - (size_t)at;
                dropped = (kw_block_header *)malloc(ndropped * sizeof *dropped);
                if (!dropped) { goto fail; }
                memcpy(dropped, s->h + at, ndropped * sizeof *dropped);
                kw_u256_zero(&dropped_work);
                fork_at = at;                     /* so the exit path restores it */
                if (!kw_sync_chainwork(s, (uint32_t)at, (uint32_t)s->count, &dropped_work)) goto fail;
            } else if (at < fork_at) {
                /* A second fork, lower than the first. Only the first was
                   recorded, so the headers between the two were truncated away
                   and saved nowhere: the restore put back the first tail at the
                   first fork, which is above where the store now ended, and the
                   next sync appended the peer's lighter chain as an ordinary
                   extension with nothing compared. Those headers are still ours
                   and untouched, since everything below the first fork is. */
                size_t extra = (size_t)(fork_at - at);
                kw_block_header *nd = (kw_block_header *)realloc(dropped,
                                        (ndropped + extra) * sizeof *nd);
                if (!nd) { goto fail; }
                dropped = nd;
                memmove(dropped + extra, dropped, ndropped * sizeof *dropped);
                memcpy(dropped, s->h + at, extra * sizeof *dropped);
                ndropped += extra;
                if (!kw_sync_chainwork(s, (uint32_t)at, (uint32_t)fork_at, &dropped_work)) goto fail;
                fork_at = at;
            }
            if (kw_net_verbose)
                fprintf(stderr, "[headers] a fork at %ld, %zu header(s) of ours above it\n",
                        at, s->count - (size_t)at);
            kw_headerstore_truncate(s, (uint32_t)at);
            cpi = cp_from(cp, (uint32_t)s->count + 1);
        }

        size_t nout = 0;
        /* the height the first header of this message will take, so the callback can
           tell what is above the anchor and what is already pinned by one */
        struct feed f = { q, from_height, (uint32_t)s->count + 1, 0 };
        if (kw_msg_headers_parse_cb(pl, pn, batch, KW_MAX_HEADERS, &nout,
                                    q ? on_header : NULL, &f) != 1) { goto fail; }
        if (f.stopped) { goto fail; }
        if (nout == 0) break;                    /* peer has nothing after our tip */

        for (size_t i = 0; i < nout; i++) {
            /* The difficulty a header claims has to be the one the chain demands of
               it, or work proves only that energy went somewhere. Checked before the
               append, so the store never holds a header the rule refuses, and with
               the store still ending at the previous height. */
            uint32_t height = (uint32_t)s->count + 1;
            if (cpi < cp->ncheckpoints && cp->checkpoints[cpi].height == height) {
                uint8_t want[32];
                if (!unhex_rev(cp->checkpoints[cpi].hash, want) ||
                    memcmp(want, batch[i].hash, 32) != 0) {
                    if (kw_net_verbose)
                        fprintf(stderr, "[headers] %u is not the block this release "
                                        "pins at that height\n", height);
                    goto fail;
                }
                cpi++;
            }
            if (!kw_sync_bits_ok(s, cp, height, kw_header_bits(batch[i].raw))) {
                if (kw_net_verbose)
                    fprintf(stderr, "[headers] %u carries the wrong difficulty\n", height);
                goto fail;
            }
            if (!kw_sync_version_ok(cp, height, kw_header_version(batch[i].raw))) {
                if (kw_net_verbose)
                    fprintf(stderr, "[headers] %u does not say it belongs to this chain\n", height);
                goto fail;
            }
            /* The retarget rule is derived from these timestamps, so a chain that
               can write them freely writes its own difficulty. */
            if (!kw_sync_time_ok(s, cp, height, kw_header_time(batch[i].raw), now)) {
                /* Core refuses this header and keeps the chain below it, and so
                   does this: failing the call threw away every header the sync
                   had already checked, which on a fresh chain is all of them. */
                if (kw_net_verbose)
                    fprintf(stderr, "[headers] %u is timestamped outside what the chain "
                                    "before it allows; keeping the %ld below it\n",
                            height, total);
                stop = 1;
                break;
            }
            if (!kw_headerstore_append(s, &batch[i])) { goto fail; }
            total++;
        }
        if (kw_net_verbose) fprintf(stderr, "[headers] %ld synced\n", total);
        if (stop) break;
    }

    /* A chain that stops below the newest anchor is not this chain. Without this a
       short fabricated one never reaches a checkpoint to be caught by, which is
       exactly how a peer would serve a wallet a payment that never happened. */
    if (cp->ncheckpoints) {
        uint32_t last = cp->checkpoints[cp->ncheckpoints - 1].height;
        if ((uint32_t)s->count < last) {
            if (kw_net_verbose)
                fprintf(stderr, "[headers] the peer's chain ends at %zu, below the %u "
                                "this release pins\n", s->count, last);
            goto fail;
        }
    }
    if (fork_at >= 0) {
        kw_u256 gained;
        kw_u256_zero(&gained);
        int heavier = kw_sync_chainwork(s, (uint32_t)fork_at, (uint32_t)s->count, &gained) &&
                      kw_u256_cmp(&gained, &dropped_work) > 0;
        if (!heavier) {
            if (kw_net_verbose)
                fprintf(stderr, "[headers] the fork at %ld carries no more work than the "
                                "%zu header(s) it would replace; keeping ours\n",
                        fork_at, ndropped);
            goto fail;
        }
        free(dropped);
        dropped = NULL;
        fork_at = -1;
    }
    free(batch);
    return total;

fail:
    /* one exit: whatever went wrong, a tail dropped for a fork that never proved
       itself goes back, since the caller's store is not this function's to shorten */
    if (fork_at >= 0) {
        kw_headerstore_truncate(s, (uint32_t)fork_at);
        for (size_t i = 0; i < ndropped; i++)
            if (!kw_headerstore_append(s, &dropped[i])) break;
        free(dropped);
    }
    free(batch);
    return -1;
}
