/* koinu.dog - parallel header sync tests (offline, over socketpairs)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * A synthetic 8-header chain split into two checkpointed segments. Each
 * segment is served over its own socketpair and written out of order into a
 * created cache, which must then load as one linked chain. A wrong terminal
 * hash and a broken in-segment link are each refused.
 *
 * Then the whole of kw_psync_headers over real sockets: several peers in this
 * process, worker threads racing for segments, the writes landing at the right
 * offsets and the rename at the end. That path had no test at all, which for a
 * threaded downloader writing a cache other code trusts is the wrong thing to
 * have untested. */

#include "psync.h"
#include "headers.h"
#include "proto.h"
#include "chainparams.h"
#include "psyncnode.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define NH 8

/* one headers message: varint count, then 80 raw + varint(0) txcount each */
static size_t mk_headers(uint8_t *out, const kw_block_header *h, size_t n)
{
    size_t k = 0;
    out[k++] = (uint8_t)n;
    for (size_t i = 0; i < n; i++) {
        memcpy(out + k, h[i].raw, KW_HEADER_LEN); k += KW_HEADER_LEN;
        out[k++] = 0;
    }
    return k;
}

/* serve one preloaded headers message, run kw_psync_segment against it, and
   flush the verified segment to (fd) the way psync's winner does */
static int run_segment(const uint8_t *msg, size_t mlen, int fd,
                       const uint8_t start_hash[32], uint32_t h0,
                       const uint8_t end_hash[32], uint32_t h1)
{
    uint32_t magic = KW_DOGE_REGTEST.magic;
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return -1;
    struct timeval tv = { 5, 0 };
    setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    uint8_t frame[2048];
    size_t fn = kw_msg_serialize(magic, "headers", msg, mlen, frame, sizeof frame);
    if (!fn || write(sv[1], frame, fn) != (ssize_t)fn) { close(sv[0]); close(sv[1]); return -1; }

    kw_peer p;
    kw_peer_from_fd(&p, magic, sv[0]);
    uint8_t buf[NH * KW_HDR_REC];
    int r = kw_psync_segment(&p, buf, start_hash, h0, end_hash, h1);
    if (r == 1 && pwrite(fd, buf, (size_t)(h1 - h0) * KW_HDR_REC,
                         4 + (off_t)h0 * KW_HDR_REC) != (ssize_t)((h1 - h0) * KW_HDR_REC)) r = -1;
    kw_peer_close(&p);
    close(sv[1]);
    return r;
}

int main(void)
{
    /* a linked chain hanging off a fake anchor hash */
    uint8_t anchor[32]; memset(anchor, 0x77, 32);
    kw_block_header h[NH];
    uint8_t raw[KW_HEADER_LEN];
    const uint8_t *prev = anchor;
    for (int i = 0; i < NH; i++) {
        memset(raw, 0, sizeof raw); raw[0] = (uint8_t)(i + 1);
        memcpy(raw + 4, prev, 32);
        kw_block_header_parse(raw, KW_HEADER_LEN, &h[i]);
        prev = h[i].hash;
    }

    const char *tmp = "test_psync_cache.tmp";
    remove(tmp);
    if (!kw_headerstore_create(tmp, NH)) { fprintf(stderr, "FAIL: create\n"); return 1; }
    FILE *f = fopen(tmp, "r+b");
    if (!f) { fprintf(stderr, "FAIL: open\n"); return 1; }
    int fd = fileno(f);

    uint8_t msg[1024]; size_t mlen;

    /* second segment first: out-of-order assembly must still link on load */
    mlen = mk_headers(msg, h + 4, 4);
    if (run_segment(msg, mlen, fd, h[3].hash, 4, h[7].hash, 8) != 1) {
        fprintf(stderr, "FAIL: segment 2\n"); return 1;
    }
    mlen = mk_headers(msg, h, 4);
    if (run_segment(msg, mlen, fd, anchor, 0, h[3].hash, 4) != 1) {
        fprintf(stderr, "FAIL: segment 1\n"); return 1;
    }
    fclose(f);

    kw_headerstore s; kw_headerstore_init(&s);
    if (!kw_headerstore_load(&s, tmp) || s.count != NH ||
        memcmp(kw_headerstore_tip(&s)->hash, h[NH - 1].hash, 32) != 0) {
        fprintf(stderr, "FAIL: assembled cache load\n"); return 1;
    }
    kw_headerstore_free(&s);

    /* a segment whose last header does not hash to the end checkpoint fails */
    f = fopen(tmp, "r+b"); fd = fileno(f);
    mlen = mk_headers(msg, h, 4);
    if (run_segment(msg, mlen, fd, anchor, 0, h[4].hash, 4) != 0) {
        fprintf(stderr, "FAIL: wrong terminal accepted\n"); return 1;
    }

    /* a batch with a header that does not link to the one before it fails */
    kw_block_header bad[4];
    memcpy(bad, h, sizeof bad);
    memset(raw, 0, sizeof raw); raw[0] = 0x99; memset(raw + 4, 0x55, 32);
    kw_block_header_parse(raw, KW_HEADER_LEN, &bad[2]);
    mlen = mk_headers(msg, bad, 4);
    if (run_segment(msg, mlen, fd, anchor, 0, h[3].hash, 4) != 0) {
        fprintf(stderr, "FAIL: broken link accepted\n"); return 1;
    }
    fclose(f);
    remove(tmp);

    /* And the whole downloader over real sockets: three peers in this process,
       worker threads claiming and racing segments, each winner's records landing
       at its own offset, and the rename at the end. Until this, kw_psync_headers
       had no test: only kw_psync_segment did, which is the part that verifies and
       not the part that decides what gets written where. */
    {
        enum { PN = 40, SEG = 10, NODES = 3 };
        kw_block_header ch[PN];
        uint8_t anch[32];
        memset(anch, 0x11, 32);
        const uint8_t *pv = anch;
        for (int i = 0; i < PN; i++) {
            memset(raw, 0, sizeof raw);
            raw[0] = (uint8_t)(i + 1);
            raw[68] = (uint8_t)i;                  /* so no two hash alike */
            memcpy(raw + 4, pv, 32);
            kw_block_header_parse(raw, KW_HEADER_LEN, &ch[i]);
            pv = ch[i].hash;
        }

        /* anchors every SEG, the genesis slot holding the chain's own base */
        char hexes[PN / SEG + 1][65];
        kw_checkpoint cps[PN / SEG + 1];
        for (int i = 0; i <= PN / SEG; i++) {
            const uint8_t *hh = i ? ch[i * SEG - 1].hash : anch;
            for (int b = 0; b < 32; b++) snprintf(hexes[i] + b * 2, 3, "%02x", hh[31 - b]);
            cps[i].height = (uint32_t)(i * SEG);
            cps[i].hash = hexes[i];
        }
        kw_chainparams pcp = KW_DOGE_REGTEST;
        pcp.checkpoints = cps;
        pcp.ncheckpoints = PN / SEG + 1;
        pcp.genesis = hexes[0];

        kw_testnode nd[NODES];
        char addr[NODES][32];
        const char *hosts[NODES];
        for (int i = 0; i < NODES; i++) {
            /* a small batch so a segment takes several rounds, which is where the
               per-round link check and the stop hash actually get exercised */
            if (!kw_testnode_start(&nd[i], pcp.magic, ch, PN, 4)) {
                fprintf(stderr, "FAIL: could not start test node %d\n", i); return 1;
            }
            snprintf(addr[i], sizeof addr[i], "127.0.0.1:%u", (unsigned)nd[i].port);
            hosts[i] = addr[i];
        }

        const char *cache = "test_psync_net.tmp";
        remove(cache);
        const char *fastest = NULL;
        long r = kw_psync_headers(&pcp, hosts, NODES, 0, 0, NODES, cache, &fastest);
        for (int i = 0; i < NODES; i++) kw_testnode_stop(&nd[i]);

        if (r != PN) { fprintf(stderr, "FAIL: parallel fill returned %ld, want %d\n", r, PN); return 1; }

        /* the cache has to load as one linked chain and end where the chain does,
           which is what says every segment landed at the right offset */
        kw_headerstore ps;
        kw_headerstore_init(&ps);
        if (!kw_headerstore_load(&ps, cache)) { fprintf(stderr, "FAIL: filled cache will not load\n"); return 1; }
        if (ps.count != PN) { fprintf(stderr, "FAIL: cache holds %zu, want %d\n", ps.count, PN); return 1; }
        for (int i = 0; i < PN; i++)
            if (memcmp(ps.h[i].hash, ch[i].hash, 32) != 0) {
                fprintf(stderr, "FAIL: height %d is not the header served\n", i + 1); return 1;
            }
        kw_headerstore_free(&ps);

        /* a second run leaves the cache alone rather than refilling it */
        if (kw_psync_headers(&pcp, hosts, NODES, 0, 0, NODES, cache, NULL) != 0) {
            fprintf(stderr, "FAIL: refilled a cache that already existed\n"); return 1;
        }
        remove(cache);

        /* and with nothing listening it fails and leaves no cache behind, so the
           caller falls back to the sequential sync rather than onto a part file */
        const char *dead[1] = { "127.0.0.1:1" };
        if (kw_psync_headers(&pcp, dead, 1, 0, 0, 2, cache, NULL) != -1) {
            fprintf(stderr, "FAIL: a fill with no peer did not fail\n"); return 1;
        }
        FILE *leftover = fopen(cache, "rb");
        if (leftover) { fclose(leftover); fprintf(stderr, "FAIL: a failed fill left a cache\n"); return 1; }
        char part[64]; snprintf(part, sizeof part, "%s.part", cache);
        leftover = fopen(part, "rb");
        if (leftover) { fclose(leftover); fprintf(stderr, "FAIL: a failed fill left its part file\n"); return 1; }
    }

    printf("psync ok: two segments assembled out of order and loaded linked, wrong\n"
           "  terminal and broken link refused, and 40 headers filled over 4 segments\n"
           "  by 3 threads against 3 peers, landing linked and in order\n");
    return 0;
}
