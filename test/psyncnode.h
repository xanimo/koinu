/* koinu.dog - a peer that serves one chain, inside the test process
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * test/fakenode.c answers an empty headers message, which is enough to get a
 * daemon listening and no use for anything that has to download a chain. This
 * serves a real one: it finds the caller's locator in the chain it holds and
 * replies with what follows, stopping at hash_stop, which is what kw_psync_segment
 * and the chain-selection sync both need from a peer.
 *
 * It listens on an ephemeral port and reports it, so several can run at once in
 * one process and be named as 127.0.0.1:PORT. A thread per connection, because a
 * parallel download opens one per worker and a node answering them one at a time
 * would serialise the thing under test. */

#ifndef KOINU_PSYNCNODE_H
#define KOINU_PSYNCNODE_H

#include "headers.h"
#include "msg.h"
#include "proto.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct {
    int                     ls;
    uint16_t                port;
    uint32_t                magic;
    const kw_block_header  *chain;      /* heights 1..n, in order */
    int                     n;
    int                     maxbatch;   /* headers per reply, 0 for all of them */
    pthread_t               tid;
    volatile int            stop;
} kw_testnode;

static int kwtn_write_all(int fd, const uint8_t *b, size_t n)
{
    while (n) {
        ssize_t w = write(fd, b, n);
        if (w <= 0) return 0;
        b += (size_t)w; n -= (size_t)w;
    }
    return 1;
}

static int kwtn_send(int fd, uint32_t magic, const char *cmd, const uint8_t *pl, size_t pn)
{
    uint8_t *frame = (uint8_t *)malloc(pn + 64);
    if (!frame) return 0;
    size_t fn = kw_msg_serialize(magic, cmd, pl, pn, frame, pn + 64);
    int ok = fn && kwtn_write_all(fd, frame, fn);
    free(frame);
    return ok;
}

/* the height whose hash is (h), or 0 for "not mine" */
static int kwtn_height_of(const kw_testnode *nd, const uint8_t h[32])
{
    for (int i = nd->n; i-- > 0; )
        if (memcmp(nd->chain[i].hash, h, 32) == 0) return i + 1;
    return 0;
}

/* one getheaders: take the first locator hash we recognise and serve what comes
   after it, stopping at hash_stop when it is one of ours */
static int kwtn_headers(const kw_testnode *nd, int fd, const uint8_t *pl, size_t pn)
{
    if (pn < 4 + 1) return 0;
    size_t off = 4;
    uint8_t pfx = pl[off++];
    uint64_t nloc = pfx;
    if (pfx >= 0xfd) {
        int k = pfx == 0xfd ? 2 : pfx == 0xfe ? 4 : 8;
        if (off + (size_t)k > pn) return 0;
        nloc = 0;
        for (int i = 0; i < k; i++) nloc |= (uint64_t)pl[off + i] << (8 * i);
        off += (size_t)k;
    }
    if (nloc > 64 || off + nloc * 32 + 32 > pn) return 0;

    int from = 0;
    for (uint64_t i = 0; i < nloc && !from; i++) from = kwtn_height_of(nd, pl + off + i * 32);
    off += nloc * 32;

    int stop_at = nd->n;
    if (memcmp(pl + off, "\0\0\0\0\0\0\0\0", 8) != 0) {
        int s = kwtn_height_of(nd, pl + off);
        if (s) stop_at = s;
    }

    int count = stop_at - from;
    if (count < 0) count = 0;
    if (nd->maxbatch && count > nd->maxbatch) count = nd->maxbatch;

    size_t cap = 9 + (size_t)count * (KW_HEADER_LEN + 1);
    uint8_t *body = (uint8_t *)malloc(cap);
    if (!body) return 0;
    size_t k = 0;
    if (count < 0xfd) body[k++] = (uint8_t)count;
    else { body[k++] = 0xfd; body[k++] = (uint8_t)count; body[k++] = (uint8_t)(count >> 8); }
    for (int i = 0; i < count; i++) {
        memcpy(body + k, nd->chain[from + i].raw, KW_HEADER_LEN);
        k += KW_HEADER_LEN;
        body[k++] = 0;                              /* transaction count */
    }
    int ok = kwtn_send(fd, nd->magic, "headers", body, k);
    free(body);
    return ok;
}

struct kwtn_conn { const kw_testnode *nd; int fd; };

static void *kwtn_serve_conn(void *arg)
{
    struct kwtn_conn *c = (struct kwtn_conn *)arg;
    const kw_testnode *nd = c->nd;
    int fd = c->fd;
    free(c);

    uint8_t buf[65536];
    size_t have = 0;
    for (;;) {
        ssize_t r = read(fd, buf + have, sizeof buf - have);
        if (r <= 0) break;
        have += (size_t)r;
        for (;;) {
            char cmd[13]; const uint8_t *pl = NULL; size_t pn = 0;
            int used = kw_msg_parse(nd->magic, buf, have, cmd, &pl, &pn);
            if (used <= 0) { if (used < 0) have = 0; break; }

            if (!strcmp(cmd, "version")) {
                kw_msg_version v;
                memset(&v, 0, sizeof v);
                v.version = KW_PROTOCOL_VERSION;
                v.timestamp = 1700000000;
                kw_netaddr_ipv4(v.recv_ip, 127, 0, 0, 1);
                kw_netaddr_ipv4(v.from_ip, 127, 0, 0, 1);
                v.nonce = 0x5151515151515151ULL;
                v.user_agent = "/testnode:0/";
                v.start_height = nd->n;
                uint8_t vb[256];
                size_t vn = kw_msg_version_build(&v, vb, sizeof vb);
                if (!vn || !kwtn_send(fd, nd->magic, "version", vb, vn)) goto done;
                if (!kwtn_send(fd, nd->magic, "verack", NULL, 0)) goto done;
            } else if (!strcmp(cmd, "getheaders")) {
                if (!kwtn_headers(nd, fd, pl, pn)) goto done;
            } else if (!strcmp(cmd, "ping")) {
                if (!kwtn_send(fd, nd->magic, "pong", pl, pn)) goto done;
            }

            memmove(buf, buf + used, have - (size_t)used);
            have -= (size_t)used;
        }
        if (have == sizeof buf) have = 0;
    }
done:
    close(fd);
    return NULL;
}

static void *kwtn_accept(void *arg)
{
    kw_testnode *nd = (kw_testnode *)arg;
    for (;;) {
        int fd = accept(nd->ls, NULL, NULL);
        if (fd < 0) break;
        if (nd->stop) { close(fd); break; }
        struct kwtn_conn *c = (struct kwtn_conn *)malloc(sizeof *c);
        if (!c) { close(fd); continue; }
        c->nd = nd; c->fd = fd;
        pthread_t t;
        if (pthread_create(&t, NULL, kwtn_serve_conn, c) != 0) { close(fd); free(c); continue; }
        pthread_detach(t);
    }
    return NULL;
}

/* Start one. Returns 1 with nd->port set to the ephemeral port it took. */
static int kw_testnode_start(kw_testnode *nd, uint32_t magic,
                             const kw_block_header *chain, int n, int maxbatch)
{
    memset(nd, 0, sizeof *nd);
    nd->magic = magic; nd->chain = chain; nd->n = n; nd->maxbatch = maxbatch;

    nd->ls = socket(AF_INET, SOCK_STREAM, 0);
    if (nd->ls < 0) return 0;
    int one = 1;
    setsockopt(nd->ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    if (bind(nd->ls, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(nd->ls, 8) != 0) {
        close(nd->ls); return 0;
    }
    socklen_t sl = sizeof sa;
    if (getsockname(nd->ls, (struct sockaddr *)&sa, &sl) != 0) { close(nd->ls); return 0; }
    nd->port = ntohs(sa.sin_port);

    if (pthread_create(&nd->tid, NULL, kwtn_accept, nd) != 0) { close(nd->ls); return 0; }
    return 1;
}

static void kw_testnode_stop(kw_testnode *nd)
{
    nd->stop = 1;
    shutdown(nd->ls, SHUT_RDWR);
    close(nd->ls);
    pthread_join(nd->tid, NULL);
}

#endif /* KOINU_PSYNCNODE_H */
