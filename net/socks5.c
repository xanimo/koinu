/* koinu.dog - SOCKS5 dialer (for Tor)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "socks5.h"
#include "rng.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

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

static int read_all(int fd, uint8_t *b, size_t n)
{
    while (n) {
        ssize_t r = read(fd, b, n);
        if (r < 0) { if (errno == EINTR) continue; return 0; }
        if (r == 0) return 0;             /* peer closed early */
        b += r; n -= (size_t)r;
    }
    return 1;
}

int kw_socks5_connect(const char *proxy_host, int proxy_port,
                      const char *dest_host, int dest_port, int timeout_sec)
{
    size_t hl = strlen(dest_host);
    if (hl == 0 || hl > 255 || dest_port < 0 || dest_port > 0xffff) return -1;

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)proxy_port);
    if (inet_pton(AF_INET, proxy_host, &sa.sin_addr) != 1) return -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct timeval tv = { timeout_sec, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    int on = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);

    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) { close(fd); return -1; }

    /* Greeting: version 5, offering username/password as well as no
       authentication. Tor keys a circuit on the credentials, so a random pair per
       connection puts each peer on its own circuit and its own exit: with no
       credentials offered, every connection kwd's resident peers, psync's workers
       and the three-way work comparison make can share one exit, and that exit
       then sees plaintext p2p for all of them and can withhold from all of them,
       which is the comparison the threat model leans on. A proxy that is not tor
       either accepts the pair or picks method 0, and both are handled. */
    uint8_t greet[4] = { 0x05, 0x02, 0x00, 0x02 };
    uint8_t rep[2];
    if (!write_all(fd, greet, sizeof greet) || !read_all(fd, rep, sizeof rep) ||
        rep[0] != 0x05) { close(fd); return -1; }

    if (rep[1] == 0x02) {                  /* RFC 1929: a random pair, never reused */
        uint8_t iso[32];
        if (!kw_random_bytes(iso, sizeof iso)) { close(fd); return -1; }
        uint8_t auth[3 + 16 + 16];
        size_t an = 0;
        auth[an++] = 0x01;                 /* the subnegotiation's own version */
        auth[an++] = 16;
        for (int i = 0; i < 16; i++) auth[an++] = (uint8_t)('a' + (iso[i] & 15));
        auth[an++] = 16;
        for (int i = 16; i < 32; i++) auth[an++] = (uint8_t)('a' + (iso[i] & 15));
        uint8_t ar[2];
        if (!write_all(fd, auth, an) || !read_all(fd, ar, sizeof ar) ||
            ar[0] != 0x01 || ar[1] != 0x00) { close(fd); return -1; }
    } else if (rep[1] != 0x00) { close(fd); return -1; }

    /* CONNECT to a domain name */
    uint8_t req[4 + 1 + 255 + 2];
    size_t n = 0;
    req[n++] = 0x05;                       /* version */
    req[n++] = 0x01;                       /* CONNECT */
    req[n++] = 0x00;                       /* reserved */
    req[n++] = 0x03;                       /* address type: domain name */
    req[n++] = (uint8_t)hl;
    memcpy(req + n, dest_host, hl); n += hl;
    req[n++] = (uint8_t)((dest_port >> 8) & 0xff);
    req[n++] = (uint8_t)(dest_port & 0xff);
    if (!write_all(fd, req, n)) { close(fd); return -1; }

    /* reply: version, rep, reserved, atyp, then a bound address we discard */
    uint8_t r[4];
    if (!read_all(fd, r, 4) || r[0] != 0x05 || r[1] != 0x00) { close(fd); return -1; }
    size_t skip;
    if (r[3] == 0x01) skip = 4;            /* IPv4 */
    else if (r[3] == 0x04) skip = 16;      /* IPv6 */
    else if (r[3] == 0x03) {               /* domain name: length-prefixed */
        uint8_t l;
        if (!read_all(fd, &l, 1)) { close(fd); return -1; }
        skip = l;
    } else { close(fd); return -1; }
    /* A domain bound address is length-prefixed by a byte the proxy chooses, so
       this has to hold 255 of them and not the 16 an IPv6 address needs. The
       address is discarded either way; it still has to be read off the socket.
       RFC 1928 permits ATYP 0x03 in a reply, so an odd-but-honest proxy reaches
       this as readily as a hostile one. */
    uint8_t bnd[255 + 2];
    if (!read_all(fd, bnd, skip + 2)) { close(fd); return -1; }   /* addr + port */

    return fd;
}
