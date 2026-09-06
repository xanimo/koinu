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

#include "chainparams.h"

typedef struct {
    int      fd;
    uint32_t magic;
    uint8_t *rbuf;  size_t rcap, rlen;   /* unparsed bytes off the wire */
    uint8_t *msg;   size_t mcap;         /* holds the last parsed payload */
    int32_t  peer_version;
    int32_t  peer_height;
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
   timeout; -1 on a framing/checksum/socket error. */
int  kw_peer_recv(kw_peer *p, char cmd[13], const uint8_t **payload, size_t *plen);

/* Send version, exchange verack (answering any ping), recording the peer's
   version and advertised height. Returns 1 once verack is received. */
int  kw_peer_handshake(kw_peer *p, int32_t start_height);

void kw_peer_close(kw_peer *p);

#endif /* KOINU_PEER_H */
