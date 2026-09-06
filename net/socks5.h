/* koinu.dog - SOCKS5 dialer (for Tor)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Connects out through a SOCKS5 proxy, passing the destination as a hostname so
 * the proxy resolves it. With Tor's SocksPort that reaches .onion services and
 * routes clearnet peers over Tor without leaking a DNS lookup. No proxy auth. */

#ifndef KOINU_SOCKS5_H
#define KOINU_SOCKS5_H

/* Dial (dest_host:dest_port) through the SOCKS5 proxy at (proxy_host:proxy_port,
   a numeric IPv4, typically 127.0.0.1). dest_host is sent as a name (<= 255
   bytes), so .onion works. Returns a connected socket fd with send/recv
   timeouts set, or -1 on any failure. */
int kw_socks5_connect(const char *proxy_host, int proxy_port,
                      const char *dest_host, int dest_port, int timeout_sec);

#endif /* KOINU_SOCKS5_H */
