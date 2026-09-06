/* dogewallet - p2p peer connection and handshake
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * A single outbound peer: a TCP socket, a growable receive buffer that feeds
 * dw_msg_parse as bytes arrive, and the version/verack handshake. No event
 * library; the caller drives recv in a loop. Tor comes later as a SOCKS5 dialer
 * in front of connect. */

#ifndef DOGEWALLET_PEER_H
#define DOGEWALLET_PEER_H

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
} dw_peer;

/* Wrap an already-connected fd (used by tests over a socketpair). Returns 1. */
int  dw_peer_from_fd(dw_peer *p, uint32_t magic, int fd);

/* Connect to a numeric IPv4 host:port with a receive/send timeout. Returns 1. */
int  dw_peer_connect(dw_peer *p, const dw_chainparams *cp,
                     const char *host, int port, int timeout_sec);

/* Frame (cmd, payload) and write it. Returns 1 on success. */
int  dw_peer_send(dw_peer *p, const char *cmd, const uint8_t *payload, size_t plen);

/* Read one message. Returns 1 with (cmd) NUL-terminated and (payload)/(plen)
   pointing at peer-owned storage valid until the next recv; 0 on clean EOF or
   timeout; -1 on a framing/checksum/socket error. */
int  dw_peer_recv(dw_peer *p, char cmd[13], const uint8_t **payload, size_t *plen);

/* Send version, exchange verack (answering any ping), recording the peer's
   version and advertised height. Returns 1 once verack is received. */
int  dw_peer_handshake(dw_peer *p, int32_t start_height);

void dw_peer_close(dw_peer *p);

#endif /* DOGEWALLET_PEER_H */
