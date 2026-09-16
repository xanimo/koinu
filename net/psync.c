/* koinu.dog - parallel checkpointed header download
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "psync.h"
#include "headers.h"
#include "sync.h"
#include "msg.h"
#include "hex.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* display hex to internal order */
static int unhex_rev(const char *hex, uint8_t out[32])
{
    uint8_t disp[32];
    if (!kw_hex_decode(hex, 64, disp, 32)) return 0;
    for (int i = 0; i < 32; i++) out[i] = disp[31 - i];
    return 1;
}

int kw_psync_segment(kw_peer *p, uint8_t *out,
                     const uint8_t start_hash[32], uint32_t start_height,
                     const uint8_t end_hash[32], uint32_t end_height)
{
    kw_block_header *batch = (kw_block_header *)malloc(KW_MAX_HEADERS * sizeof *batch);
    if (!batch) return 0;

    uint8_t cur[32]; memcpy(cur, start_hash, 32);
    uint32_t h = start_height;
    int ok = 0;

    while (h < end_height) {
        uint8_t body[128];
        size_t bn = kw_msg_getheaders_build(KW_PROTOCOL_VERSION,
                                            (const uint8_t (*)[32])cur, 1, end_hash,
                                            body, sizeof body);
        if (!bn || !kw_peer_send(p, "getheaders", body, bn)) goto out;

        char cmd[13]; const uint8_t *pl = NULL; size_t pn = 0;
        int got = 0;
        while (kw_peer_recv(p, cmd, &pl, &pn) == 1) {
            if (!strcmp(cmd, "headers")) { got = 1; break; }
            if (!strcmp(cmd, "ping")) kw_peer_send(p, "pong", pl, pn);
        }
        if (!got) goto out;

        size_t nout = 0;
        if (kw_msg_headers_parse(pl, pn, batch, KW_MAX_HEADERS, &nout) != 1 || nout == 0) goto out;

        for (size_t i = 0; i < nout; i++) {
            if (h >= end_height) break;               /* peer sent past the stop */
            if (memcmp(kw_block_header_prev(&batch[i]), cur, 32) != 0) goto out;
            uint8_t *rec = out + (size_t)(h - start_height) * KW_HDR_REC;
            memcpy(rec, batch[i].raw, KW_HEADER_LEN);
            memcpy(rec + KW_HEADER_LEN, batch[i].hash, 32);
            memcpy(cur, batch[i].hash, 32);
            h++;
        }
    }
    ok = memcmp(cur, end_hash, 32) == 0;              /* terminal anchor */
out:
    free(batch);
    return ok;
}

#define KW_PSYNC_MAX_HOSTS 16
#define KW_PSYNC_MAX_CLAIMS 2

/* The widest checkpoint gap this will buffer. Every worker holds one segment, so
   the allocation is this times the worker count: a table with one enormous gap
   would otherwise ask for hundreds of megabytes per thread without saying why.
   Mainnet's anchors sit 25000 apart. */
#define KW_PSYNC_MAX_SPAN 1000000

typedef struct {
    const kw_chainparams *cp;
    const char *const *hosts; size_t nhosts;
    int port, tor;
    int fd;
    size_t maxspan;              /* widest segment, sizes the worker buffers */
    pthread_mutex_t lock;
    int failed;
    size_t done, nseg, giveups;
    uint8_t *state;              /* per segment: 0 pending, 1 in flight, 2 done */
    uint8_t *claims;             /* workers currently on it */
    size_t host_segs[KW_PSYNC_MAX_HOSTS];    /* per-node serving tally */
    long   host_hdrs[KW_PSYNC_MAX_HOSTS];
    long   host_srv[KW_PSYNC_MAX_HOSTS];     /* headers timed, win or lose */
    double host_secs[KW_PSYNC_MAX_HOSTS];
    int    host_active[KW_PSYNC_MAX_HOSTS];  /* connections currently on it */
    int    host_fails[KW_PSYNC_MAX_HOSTS];   /* consecutive connect failures */
} psync_ctx;

static double now_mono(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + ts.tv_nsec / 1e9;
}

/* The host with the best observed rate per connection already on it, so fast
   nodes attract workers without being mobbed. An untried host scores as fast
   as anything, so every node gets explored; two straight connect failures
   bench a host, and when everyone is benched the slate wipes clean. */
static size_t pick_host(psync_ctx *c)
{
    pthread_mutex_lock(&c->lock);
    for (;;) {
        double bestscore = -1; size_t best = 0;
        for (size_t i = 0; i < c->nhosts; i++) {
            if (c->host_fails[i] >= 2) continue;
            double rate = c->host_secs[i] > 0.1 ? (double)c->host_srv[i] / c->host_secs[i] : 1e12;
            double score = rate / (double)(c->host_active[i] + 1);
            if (score > bestscore) { bestscore = score; best = i; }
        }
        if (bestscore >= 0) {
            c->host_active[best]++;
            pthread_mutex_unlock(&c->lock);
            return best;
        }
        for (size_t i = 0; i < c->nhosts; i++) c->host_fails[i] = 0;
    }
}

static void drop_host(psync_ctx *c, size_t host, int connect_failed)
{
    pthread_mutex_lock(&c->lock);
    c->host_active[host]--;
    if (connect_failed) c->host_fails[host]++;
    pthread_mutex_unlock(&c->lock);
}

/* A connect that succeeded clears the host's failure count, so "two straight
   failures" means straight. Without this a host that refused twice early stays
   benched for the rest of the run however well it served in between. */
static void host_connected(psync_ctx *c, size_t host)
{
    pthread_mutex_lock(&c->lock);
    c->host_fails[host] = 0;
    pthread_mutex_unlock(&c->lock);
}

/* True when this worker sits on a host materially slower than one it could
   reach instead. Every worker connects before any rate exists and then holds
   that connection, so pick_host only ever sees the untried-scores-infinite case
   and the rate-aware choice never happens; this is what makes it happen. Both
   sides must have served for a second before the comparison means anything, and
   the candidate must look twice as good to be worth a reconnect. */
static int worth_switching(psync_ctx *c, size_t host)
{
    int yes = 0;
    pthread_mutex_lock(&c->lock);
    if (c->host_secs[host] > 1.0 && c->host_active[host] > 0) {
        double mine = (double)c->host_srv[host] / c->host_secs[host] / (double)c->host_active[host];
        for (size_t i = 0; i < c->nhosts && !yes; i++) {
            if (i == host || c->host_fails[i] >= 2 || c->host_secs[i] <= 1.0) continue;
            double r = (double)c->host_srv[i] / c->host_secs[i] / (double)(c->host_active[i] + 1);
            if (r > 2.0 * mine) yes = 1;
        }
    }
    pthread_mutex_unlock(&c->lock);
    return yes;
}

/* The first pending segment, else the least-claimed in-flight one so an idle
   worker races the straggler holding it. 0 when there is nothing left to do. */
static size_t get_work(psync_ctx *c)
{
    size_t pick = 0;
    pthread_mutex_lock(&c->lock);
    if (!c->failed && c->done < c->nseg) {
        for (size_t i = 1; i <= c->nseg && !pick; i++)
            if (c->state[i] == 0) pick = i;
        if (!pick) {
            uint8_t least = KW_PSYNC_MAX_CLAIMS;
            for (size_t i = 1; i <= c->nseg; i++)
                if (c->state[i] == 1 && c->claims[i] < least) { least = c->claims[i]; pick = i; }
            if (pick && kw_net_verbose)
                fprintf(stderr, "[psync] racing segment %u-%u\n",
                        c->cp->checkpoints[pick - 1].height, c->cp->checkpoints[pick].height);
        }
        if (pick) { c->state[pick] = 1; c->claims[pick]++; }
    }
    pthread_mutex_unlock(&c->lock);
    return pick;
}

static void *worker(void *arg)
{
    psync_ctx *c = (psync_ctx *)arg;
    kw_peer p; int connected = 0;
    size_t host = 0;

    uint8_t *buf = (uint8_t *)malloc(c->maxspan * KW_HDR_REC);
    if (!buf) {
        pthread_mutex_lock(&c->lock); c->failed = 1; pthread_mutex_unlock(&c->lock);
        return NULL;
    }

    for (;;) {
        size_t i = get_work(c);
        if (!i) break;

        uint8_t sh[32], eh[32];
        uint32_t h0 = c->cp->checkpoints[i - 1].height, h1 = c->cp->checkpoints[i].height;
        int done = 0;
        double dt = 0;
        if (unhex_rev(c->cp->checkpoints[i - 1].hash, sh) &&
            unhex_rev(c->cp->checkpoints[i].hash, eh)) {
            for (int attempt = 0; attempt < 3 && !done; attempt++) {
                if (!connected) {
                    host = pick_host(c);
                    const char *hn = c->hosts[host];
                    connected = c->tor
                        ? kw_peer_connect_socks5(&p, c->cp, hn, c->port, 10, "127.0.0.1", 9050)
                        : kw_peer_connect(&p, c->cp, hn, c->port, 10);
                    if (connected && !kw_peer_handshake(&p, 0)) { kw_peer_close(&p); connected = 0; }
                    if (!connected) { drop_host(c, host, 1); continue; }
                    host_connected(c, host);
                }
                double t0 = now_mono();
                if (kw_psync_segment(&p, buf, sh, h0, eh, h1)) { done = 1; dt = now_mono() - t0; }
                else { kw_peer_close(&p); connected = 0; drop_host(c, host, 0); }
            }
        }

        pthread_mutex_lock(&c->lock);
        c->claims[i]--;
        int won = done && c->state[i] != 2;           /* a race loser discards */
        if (done) {
            c->host_srv[host] += (long)(h1 - h0);     /* rate counts wins and losses */
            c->host_secs[host] += dt;
        }
        if (won) {
            c->state[i] = 2;
            c->done++;
            c->host_segs[host]++;
            c->host_hdrs[host] += (long)(h1 - h0);
            if (kw_net_verbose)
                fprintf(stderr, "[psync] segment %u-%u done via %s (%zu/%zu)\n",
                        h0, h1, c->hosts[host], c->done, c->nseg);
        } else if (!done) {
            if (c->state[i] == 1 && c->claims[i] == 0) c->state[i] = 0;   /* requeue */
            if (++c->giveups > 3 * c->nseg) c->failed = 1;
        }
        pthread_mutex_unlock(&c->lock);

        /* only the winner reaches the file, so racers never interleave */
        if (won && pwrite(c->fd, buf, (size_t)(h1 - h0) * KW_HDR_REC,
                          4 + (off_t)h0 * KW_HDR_REC) != (ssize_t)((h1 - h0) * KW_HDR_REC)) {
            pthread_mutex_lock(&c->lock); c->failed = 1; pthread_mutex_unlock(&c->lock);
            break;
        }

        /* between segments, not during one, so a switch costs only a reconnect */
        if (connected && worth_switching(c, host)) {
            if (kw_net_verbose)
                fprintf(stderr, "[psync] leaving %s for a faster host\n", c->hosts[host]);
            kw_peer_close(&p); connected = 0; drop_host(c, host, 0);
        }
    }

    if (connected) { kw_peer_close(&p); drop_host(c, host, 0); }
    free(buf);
    return NULL;
}

long kw_psync_headers(const kw_chainparams *cp, const char *const *hosts, size_t nhosts,
                      int port, int tor, int npeers, const char *path,
                      const char **best)
{
    if (best) *best = NULL;
    if (!cp->checkpoints || cp->ncheckpoints < 2 || nhosts == 0) return 0;
    if (nhosts > KW_PSYNC_MAX_HOSTS) nhosts = KW_PSYNC_MAX_HOSTS;
    FILE *f = fopen(path, "rb");
    if (f) { fclose(f); return 0; }                   /* cache exists: sync normally */

    uint32_t last = cp->checkpoints[cp->ncheckpoints - 1].height;
    char part[4200]; snprintf(part, sizeof part, "%s.part", path);
    if (!kw_headerstore_create(part, last)) return -1;

    FILE *pf = fopen(part, "r+b");
    if (!pf) { remove(part); return -1; }

    psync_ctx c;
    memset(&c, 0, sizeof c);
    c.cp = cp; c.hosts = hosts; c.nhosts = nhosts; c.port = port; c.tor = tor;
    c.fd = fileno(pf);
    c.nseg = cp->ncheckpoints - 1;
    pthread_mutex_init(&c.lock, NULL);
    for (size_t i = 1; i < cp->ncheckpoints; i++) {
        size_t span = cp->checkpoints[i].height - cp->checkpoints[i - 1].height;
        if (span > c.maxspan) c.maxspan = span;
    }
    if (c.maxspan > KW_PSYNC_MAX_SPAN) {
        fprintf(stderr, "kw: anchors %zu apart is too wide to fill in parallel\n", c.maxspan);
        fclose(pf); remove(part); return -1;
    }
    c.state = (uint8_t *)calloc(cp->ncheckpoints, 1);
    c.claims = (uint8_t *)calloc(cp->ncheckpoints, 1);
    if (!c.state || !c.claims) {
        free(c.state); free(c.claims); fclose(pf); remove(part); return -1;
    }

    if (npeers < 1) npeers = 1;
    if ((size_t)npeers > c.nseg) npeers = (int)c.nseg;
    pthread_t *th = (pthread_t *)malloc((size_t)npeers * sizeof *th);
    if (!th) { free(c.state); free(c.claims); fclose(pf); remove(part); return -1; }

    int started = 0;
    for (int i = 0; i < npeers; i++)
        if (pthread_create(&th[i], NULL, worker, &c) == 0) started++;
    for (int i = 0; i < started; i++) pthread_join(th[i], NULL);
    free(th);

    int ok = started > 0 && !c.failed && c.done == c.nseg;
    if (ok) {
        double bestrate = -1;
        for (size_t i = 0; i < nhosts; i++) {
            double rate = c.host_secs[i] > 0.1 ? (double)c.host_srv[i] / c.host_secs[i] : 0.0;
            if (best && rate > bestrate) { bestrate = rate; *best = hosts[i]; }
            if (kw_net_verbose)
                fprintf(stderr, "[psync] %s served %zu segments, %ld headers, %.0f hdr/s\n",
                        hosts[i], c.host_segs[i], c.host_hdrs[i], rate);
        }
    }
    free(c.state); free(c.claims);
    /* The records went in with pwrite, which the stdio buffer knows nothing about,
       so the flush fclose does is not what makes them durable. Renaming an
       unsynced file over the cache path publishes whatever the page cache happened
       to have written. A torn cache is caught on load, since every record has to
       link to the one before it, but caught means a re-download rather than a
       wrong answer only because that check exists. */
    if (ok && fsync(c.fd) != 0) ok = 0;
    if (fclose(pf) != 0) ok = 0;
    if (!ok || rename(part, path) != 0) { remove(part); return -1; }
    return (long)last;
}
