/* koinu.dog - p2p peer connection and handshake
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * A single outbound peer: a TCP socket, a growable receive buffer that feeds
 * kw_msg_parse as bytes arrive, and the version/verack handshake. No event
 * library; the caller drives recv in a loop. Tor comes later as a SOCKS5 dialer
 * in front of connect. */

#ifndef KOINU_PEER_H
#define KOINU_PEER_H

#include <stddef.h>
#include <stdint.h>

#include "kw_version.h"

#include "chainparams.h"

typedef struct {
    int      fd;
    uint32_t magic;
    uint8_t *rbuf;  size_t rcap, rlen;   /* unparsed bytes off the wire */
    uint8_t *msg;   size_t mcap;         /* holds the last parsed payload */
    int32_t  peer_version;
    int32_t  peer_height;
    uint64_t peer_services;              /* BIP159 service bits from its version */
    int64_t  peer_feerate;               /* last BIP133 feefilter, koinu/kB, 0 if none */
    const kw_chainparams *cp;            /* the network connected to; NULL from kw_peer_from_fd */
    int      relay;                      /* advertise tx relay in the version */
    int      timed_out;                  /* the last recv ended on SO_RCVTIMEO, not EOF */
} kw_peer;

/* Wrap an already-connected fd (used by tests over a socketpair). Returns 1. */
int  kw_peer_from_fd(kw_peer *p, uint32_t magic, int fd);

/* Connect to a numeric IPv4 host:port with a receive/send timeout. Returns 1. */
int  kw_peer_connect(kw_peer *p, const kw_chainparams *cp,
                     const char *host, int port, int timeout_sec);

/* Connect to (host:port) through a SOCKS5 proxy (Tor). (host) may be a name,
   including a .onion, resolved by the proxy. Returns 1. */
int  kw_peer_connect_socks5(kw_peer *p, const kw_chainparams *cp,
                            const char *host, int port, int timeout_sec,
                            const char *proxy_host, int proxy_port);

/* Frame (cmd, payload) and write it. Returns 1 on success. */
int  kw_peer_send(kw_peer *p, const char *cmd, const uint8_t *payload, size_t plen);

/* Read one message. Returns 1 with (cmd) NUL-terminated and (payload)/(plen)
   pointing at peer-owned storage valid until the next recv; 0 on clean EOF or
   timeout; -1 on a framing/checksum/socket error. On 0, p->timed_out says which:
   a caller that can afford to keep waiting needs to tell a quiet peer from one
   that hung up, since reading again after EOF returns 0 without blocking. */
int  kw_peer_recv(kw_peer *p, char cmd[13], const uint8_t **payload, size_t *plen);

/* How many messages a peer may send in place of the one it was asked for before
   the exchange is abandoned. A socket timeout only bounds one read, so a peer
   pinging faster than that holds a loop forever, and kwd serves one request at a
   time. net/sync.c had this bound and the other drivers did not. */
/* What this wallet calls itself on the wire, built from the one place the version
   is written down: the agent string said 0.1 for every release up to 0.2.5. */
#define KW_USER_AGENT "/koinu:" KW_VERSION "/"

#define KW_PEER_MAX_SKIP 256

/* The longest one exchange may take, whatever arrives during it. SO_RCVTIMEO
   bounds a single read and the skip counters bound what a caller is handed, so
   neither sees a peer that keeps kw_peer_recv itself busy: a feefilter is
   consumed inside it and the loop goes round again without returning. */
#define KW_PEER_EXCHANGE_SECONDS 120

/* Wait for a (want) message, answering pings and dropping at most
   KW_PEER_MAX_SKIP others. Returns 1 with (payload)/(plen) set, 0 otherwise. */
int  kw_peer_wait(kw_peer *p, const char *want, const uint8_t **payload, size_t *plen);

/* Set (relay) before the handshake to advertise tx relay. A light client asks for
   none, which is what stops a node flooding it with tx invs, and a node then
   refuses to serve a transaction back even from its own mempool: a broadcast
   that wants an acknowledgement has to ask for relay first. */
/* Send version, exchange verack (answering any ping), recording the peer's
   version and advertised height. Returns 1 once verack is received. */
int  kw_peer_handshake(kw_peer *p, int32_t start_height);

void kw_peer_close(kw_peer *p);

#endif /* KOINU_PEER_H */
