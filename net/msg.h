/* dogewallet - p2p message bodies (handshake)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * The payloads that ride inside the proto.c envelope. version is the only
 * involved one; verack is empty (frame it directly), ping/pong carry a nonce. */

#ifndef DOGEWALLET_MSG_H
#define DOGEWALLET_MSG_H

#include <stddef.h>
#include <stdint.h>

#define DW_PROTOCOL_VERSION 70015

typedef struct {
    int32_t  version;
    uint64_t services;
    int64_t  timestamp;
    uint64_t recv_services;  uint8_t recv_ip[16];  uint16_t recv_port;
    uint64_t from_services;  uint8_t from_ip[16];  uint16_t from_port;
    uint64_t nonce;
    const char *user_agent;  /* build: input; parse: points at the caller's buffer */
    int32_t  start_height;
    uint8_t  relay;          /* only present on the wire for version >= 70001 */
} dw_msg_version;

/* Fill a 16-byte address field with the IPv4-mapped form of a.b.c.d. */
void dw_netaddr_ipv4(uint8_t out[16], uint8_t a, uint8_t b, uint8_t c, uint8_t d);

/* Build/parse a version payload. parse writes the user agent into (ua) and
   points v->user_agent at it. Both return length / 1 on success, 0 on failure. */
size_t dw_msg_version_build(const dw_msg_version *v, uint8_t *out, size_t outcap);
int    dw_msg_version_parse(const uint8_t *in, size_t len, dw_msg_version *v,
                            char *ua, size_t uacap);

/* ping and pong share an 8-byte little-endian nonce. */
size_t dw_msg_ping_build(uint64_t nonce, uint8_t *out, size_t outcap);
int    dw_msg_ping_parse(const uint8_t *in, size_t len, uint64_t *nonce);

#endif /* DOGEWALLET_MSG_H */
