/* koinu.dog - p2p peer connection and handshake
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "peer.h"
#include "proto.h"
#include "msg.h"
#include "socks5.h"
#include "rng.h"
#include "mem.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define RBUF_INIT 8192
#define RBUF_MAX  (KW_MSG_HDR + KW_MSG_MAX_PAYLOAD)

static uint32_t get_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}

static int ensure_cap(uint8_t **buf, size_t *cap, size_t need)
{
    if (need <= *cap) return 1;
    if (need > RBUF_MAX) return 0;
    size_t nc = *cap ? *cap : RBUF_INIT;
    while (nc < need) nc *= 2;
    if (nc > RBUF_MAX) nc = RBUF_MAX;
    uint8_t *nb = (uint8_t *)realloc(*buf, nc);
    if (!nb) return 0;
    *buf = nb; *cap = nc;
    return 1;
}

int kw_peer_from_fd(kw_peer *p, uint32_t magic, int fd)
{
    memset(p, 0, sizeof *p);
    p->fd = fd;
    p->magic = magic;
    p->rbuf = (uint8_t *)malloc(RBUF_INIT);
    if (!p->rbuf) return 0;
    p->rcap = RBUF_INIT;
    return 1;
}

int kw_peer_connect(kw_peer *p, const kw_chainparams *cp,
                    const char *host, int port, int timeout_sec)
{
    /* HOST:PORT overrides (port), so several peers can be named on one command
       line without them all having to sit on the same one. Without it two nodes
       on one machine cannot both be reached, which is what kept the multi-peer
       paths from having an integration test. */
    char hbuf[64];
    const char *colon = strrchr(host, ':');
    if (colon && colon != host && strchr(host, ':') == colon) {
        size_t hl = (size_t)(colon - host);
        if (hl >= sizeof hbuf) return 0;
        memcpy(hbuf, host, hl);
        hbuf[hl] = '\0';
        int v = atoi(colon + 1);
        if (v > 0 && v < 65536) { port = v; host = hbuf; }
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) return 0;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 0;
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) { close(fd); return 0; }

    int on = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
    struct timeval tv = { timeout_sec, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

    if (!kw_peer_from_fd(p, cp->magic, fd)) { close(fd); return 0; }
    p->cp = cp;
    return 1;
}

int kw_peer_connect_socks5(kw_peer *p, const kw_chainparams *cp,
                           const char *host, int port, int timeout_sec,
                           const char *proxy_host, int proxy_port)
{
    int fd = kw_socks5_connect(proxy_host, proxy_port, host, port, timeout_sec);
    if (fd < 0) return 0;
    if (!kw_peer_from_fd(p, cp->magic, fd)) { close(fd); return 0; }
    p->cp = cp;
    return 1;
}

static int write_all(int fd, const uint8_t *b, size_t n)
{
    while (n) {
        ssize_t w = write(fd, b, n);
        if (w < 0) { if (errno == EINTR) continue; return 0; }
        if (w == 0) return 0;
        b += w; n -= (size_t)w;
    }
    return 1;
}

int kw_peer_send(kw_peer *p, const char *cmd, const uint8_t *payload, size_t plen)
{
    uint8_t stackbuf[KW_MSG_HDR + 512];
    uint8_t *buf = stackbuf;
    size_t need = KW_MSG_HDR + plen;
    if (need > sizeof stackbuf) { buf = (uint8_t *)malloc(need); if (!buf) return 0; }

    size_t n = kw_msg_serialize(p->magic, cmd, payload, plen, buf, need);
    int ok = n && write_all(p->fd, buf, n);
    if (buf != stackbuf) free(buf);
    return ok;
}

int kw_peer_recv(kw_peer *p, char cmd[13], const uint8_t **payload, size_t *plen)
{
    for (;;) {
        const uint8_t *pl = NULL; size_t pn = 0;
        int c = kw_msg_parse(p->magic, p->rbuf, p->rlen, cmd, &pl, &pn);
        if (c < 0) return -1;
        if (c > 0) {
            if (!ensure_cap(&p->msg, &p->mcap, pn ? pn : 1)) return -1;
            memcpy(p->msg, pl, pn);
            memmove(p->rbuf, p->rbuf + c, p->rlen - (size_t)c);
            p->rlen -= (size_t)c;
            /* capture the peer's fee floor transparently; the caller never sees it */
            if (!strcmp(cmd, "feefilter") && pn >= 8) {
                int64_t fr = 0;
                for (int i = 0; i < 8; i++) fr |= (int64_t)p->msg[i] << (8 * i);
                p->peer_feerate = fr;
                continue;
            }
            if (payload) *payload = p->msg;
            if (plen) *plen = pn;
            return 1;
        }
        /* need more: grow to the announced frame size, or by a chunk */
        if (p->rlen >= KW_MSG_HDR) {
            uint32_t l = get_le32(p->rbuf + 16);
            if (l <= KW_MSG_MAX_PAYLOAD && !ensure_cap(&p->rbuf, &p->rcap, KW_MSG_HDR + l)) return -1;
        }
        if (p->rlen == p->rcap && !ensure_cap(&p->rbuf, &p->rcap, p->rcap * 2)) return -1;

        ssize_t n = read(p->fd, p->rbuf + p->rlen, p->rcap - p->rlen);
        if (n == 0) return 0;
        if (n < 0) { if (errno == EINTR) continue; return 0; }
        p->rlen += (size_t)n;
    }
}

int kw_peer_handshake(kw_peer *p, int32_t start_height)
{
    kw_msg_version v;
    memset(&v, 0, sizeof v);
    v.version = KW_PROTOCOL_VERSION;
    v.services = 0;
    v.timestamp = (int64_t)time(NULL);
    kw_netaddr_ipv4(v.recv_ip, 0, 0, 0, 0);
    kw_netaddr_ipv4(v.from_ip, 0, 0, 0, 0);
    uint8_t nb[8];
    if (!kw_random_bytes(nb, sizeof nb)) return 0;
    for (int i = 0; i < 8; i++) v.nonce |= (uint64_t)nb[i] << (8 * i);
    v.user_agent = "/koinu:0.1/";
    v.start_height = start_height;
    v.relay = 0;                       /* no tx relay: a light client filters */

    uint8_t body[256];
    size_t bl = kw_msg_version_build(&v, body, sizeof body);
    if (!bl || !kw_peer_send(p, "version", body, bl)) return 0;

    int got_version = 0, got_verack = 0;
    while (!got_verack) {
        char cmd[13]; const uint8_t *pl = NULL; size_t pn = 0;
        if (kw_peer_recv(p, cmd, &pl, &pn) != 1) return 0;

        if (!strcmp(cmd, "version")) {
            kw_msg_version pv; char ua[256];
            if (kw_msg_version_parse(pl, pn, &pv, ua, sizeof ua)) {
                p->peer_version = pv.version;
                p->peer_height = pv.start_height;
            }
            got_version = 1;
            if (!kw_peer_send(p, "verack", NULL, 0)) return 0;
        } else if (!strcmp(cmd, "verack")) {
            got_verack = 1;
        } else if (!strcmp(cmd, "ping")) {
            kw_peer_send(p, "pong", pl, pn);
        }
        /* sendheaders, sendcmpct, feefilter, addr, etc: ignored during setup */
    }
    return got_version && got_verack;
}

void kw_peer_close(kw_peer *p)
{
    if (p->fd >= 0) close(p->fd);
    free(p->rbuf);
    free(p->msg);
    memset(p, 0, sizeof *p);
    p->fd = -1;
}
