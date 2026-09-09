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
#include <unistd.h>

/* display hex to internal order */
static int unhex_rev(const char *hex, uint8_t out[32])
{
    uint8_t disp[32];
    if (!kw_hex_decode(hex, 64, disp, 32)) return 0;
    for (int i = 0; i < 32; i++) out[i] = disp[31 - i];
    return 1;
}

int kw_psync_segment(kw_peer *p, int fd,
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
            uint8_t rec[KW_HDR_REC];
            memcpy(rec, batch[i].raw, KW_HEADER_LEN);
            memcpy(rec + KW_HEADER_LEN, batch[i].hash, 32);
            off_t off = 4 + (off_t)h * KW_HDR_REC;    /* record for height h+1 */
            if (pwrite(fd, rec, KW_HDR_REC, off) != KW_HDR_REC) goto out;
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

typedef struct {
    const kw_chainparams *cp;
    const char *const *hosts; size_t nhosts;
    int port, tor;
    int fd;
    pthread_mutex_t lock;
    size_t next;                 /* next segment index into cp->checkpoints */
    int failed;
    size_t done, nseg;
    size_t nexthost;             /* round-robin cursor for worker start hosts */
    size_t host_segs[KW_PSYNC_MAX_HOSTS];    /* per-node serving tally */
    long   host_hdrs[KW_PSYNC_MAX_HOSTS];
} psync_ctx;

static void *worker(void *arg)
{
    psync_ctx *c = (psync_ctx *)arg;
    kw_peer p; int connected = 0;

    pthread_mutex_lock(&c->lock);
    size_t host = c->nexthost++ % c->nhosts;
    pthread_mutex_unlock(&c->lock);

    for (;;) {
        pthread_mutex_lock(&c->lock);
        size_t i = c->next < c->cp->ncheckpoints ? c->next++ : 0;
        int stop = c->failed || i == 0;
        pthread_mutex_unlock(&c->lock);
        if (stop) break;

        uint8_t sh[32], eh[32];
        if (!unhex_rev(c->cp->checkpoints[i - 1].hash, sh) ||
            !unhex_rev(c->cp->checkpoints[i].hash, eh)) {
            pthread_mutex_lock(&c->lock); c->failed = 1; pthread_mutex_unlock(&c->lock);
            break;
        }
        uint32_t h0 = c->cp->checkpoints[i - 1].height, h1 = c->cp->checkpoints[i].height;

        int done = 0;
        for (int attempt = 0; attempt < 3 && !done; attempt++) {
            if (!connected) {
                const char *hn = c->hosts[host];
                connected = c->tor
                    ? kw_peer_connect_socks5(&p, c->cp, hn, c->port, 30, "127.0.0.1", 9050)
                    : kw_peer_connect(&p, c->cp, hn, c->port, 30);
                if (connected && !kw_peer_handshake(&p, 0)) { kw_peer_close(&p); connected = 0; }
                if (!connected) host = (host + 1) % c->nhosts;   /* try the next node */
            }
            if (!connected) continue;
            if (kw_psync_segment(&p, c->fd, sh, h0, eh, h1)) done = 1;
            else { kw_peer_close(&p); connected = 0; host = (host + 1) % c->nhosts; }
        }

        pthread_mutex_lock(&c->lock);
        if (done) {
            c->done++;
            c->host_segs[host]++;
            c->host_hdrs[host] += (long)(h1 - h0);
            if (kw_net_verbose)
                fprintf(stderr, "[psync] segment %u-%u done via %s (%zu/%zu)\n",
                        h0, h1, c->hosts[host], c->done, c->nseg);
        } else c->failed = 1;
        pthread_mutex_unlock(&c->lock);
        if (!done) break;
    }

    if (connected) kw_peer_close(&p);
    return NULL;
}

long kw_psync_headers(const kw_chainparams *cp, const char *const *hosts, size_t nhosts,
                      int port, int tor, int npeers, const char *path)
{
    if (!cp->checkpoints || cp->ncheckpoints < 2 || nhosts == 0) return 0;
    if (nhosts > KW_PSYNC_MAX_HOSTS) nhosts = KW_PSYNC_MAX_HOSTS;
    FILE *f = fopen(path, "rb");
    if (f) { fclose(f); return 0; }                   /* cache exists: sync normally */

    uint32_t last = cp->checkpoints[cp->ncheckpoints - 1].height;
    char part[4200]; snprintf(part, sizeof part, "%s.part", path);
    if (!kw_headerstore_create(part, last)) return -1;

    FILE *pf = fopen(part, "r+b");
    if (!pf) { remove(part); return -1; }

    psync_ctx c = { cp, hosts, nhosts, port, tor, fileno(pf),
                    PTHREAD_MUTEX_INITIALIZER, 1, 0, 0, cp->ncheckpoints - 1, 0,
                    {0}, {0} };

    if (npeers < 1) npeers = 1;
    if ((size_t)npeers > c.nseg) npeers = (int)c.nseg;
    pthread_t *th = (pthread_t *)malloc((size_t)npeers * sizeof *th);
    if (!th) { fclose(pf); remove(part); return -1; }

    int started = 0;
    for (int i = 0; i < npeers; i++)
        if (pthread_create(&th[i], NULL, worker, &c) == 0) started++;
    for (int i = 0; i < started; i++) pthread_join(th[i], NULL);
    free(th);

    int ok = started > 0 && !c.failed && c.done == c.nseg;
    if (ok && kw_net_verbose)
        for (size_t i = 0; i < nhosts; i++)
            fprintf(stderr, "[psync] %s served %zu segments, %ld headers\n",
                    hosts[i], c.host_segs[i], c.host_hdrs[i]);
    if (fclose(pf) != 0) ok = 0;
    if (!ok || rename(part, path) != 0) { remove(part); return -1; }
    return (long)last;
}
