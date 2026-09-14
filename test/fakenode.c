/* koinu.dog - the smallest peer kwd will talk to
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Listens on a TCP port, answers the handshake, and replies to every getheaders
 * with an empty headers message so the client's chain stays at zero. That is
 * enough to get kwd past startup and listening, which is what the tests about
 * its socket need. It knows nothing about blocks and serves no filters. */

#include "chainparams.h"
#include "msg.h"
#include "proto.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int send_msg(int fd, uint32_t magic, const char *cmd, const uint8_t *pl, size_t pn)
{
    uint8_t frame[4096];
    size_t fn = kw_msg_serialize(magic, cmd, pl, pn, frame, sizeof frame);
    if (!fn) return 0;
    size_t off = 0;
    while (off < fn) {
        ssize_t w = write(fd, frame + off, fn - off);
        if (w <= 0) return 0;
        off += (size_t)w;
    }
    return 1;
}

int main(int argc, char **argv)
{
    int net = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--testnet")) net = 1;
        else if (!strcmp(argv[i], "--regtest")) net = 2;
    }
    const kw_chainparams *cp = net == 1 ? &KW_DOGE_TESTNET : net == 2 ? &KW_DOGE_REGTEST : &KW_DOGE_MAINNET;

    signal(SIGPIPE, SIG_IGN);
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0) return 1;
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;                                    /* the kernel picks it */
    if (bind(ls, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(ls, 4) != 0) return 1;

    socklen_t sl = sizeof sa;
    if (getsockname(ls, (struct sockaddr *)&sa, &sl) != 0) return 1;
    printf("%u\n", (unsigned)ntohs(sa.sin_port));       /* the caller reads this */
    fflush(stdout);

    int fd = accept(ls, NULL, NULL);
    if (fd < 0) return 1;
    close(ls);

    uint8_t buf[65536];
    size_t have = 0;
    for (;;) {
        ssize_t r = read(fd, buf + have, sizeof buf - have);
        if (r <= 0) break;
        have += (size_t)r;

        for (;;) {
            char cmd[13];
            const uint8_t *pl = NULL;
            size_t pn = 0;
            int c = kw_msg_parse(cp->magic, buf, have, cmd, &pl, &pn);
            if (c <= 0) { if (c < 0) have = 0; break; }   /* need more, or resync */

            if (!strcmp(cmd, "version")) {
                kw_msg_version v;
                memset(&v, 0, sizeof v);
                v.version = KW_PROTOCOL_VERSION;
                v.timestamp = 1700000000;
                kw_netaddr_ipv4(v.recv_ip, 127, 0, 0, 1);
                kw_netaddr_ipv4(v.from_ip, 127, 0, 0, 1);
                v.nonce = 0x1122334455667788ULL;
                v.user_agent = "/fakenode:0/";
                v.start_height = 0;
                uint8_t body[256];
                size_t bl = kw_msg_version_build(&v, body, sizeof body);
                if (!bl || !send_msg(fd, cp->magic, "version", body, bl)) goto done;
                if (!send_msg(fd, cp->magic, "verack", NULL, 0)) goto done;
            } else if (!strcmp(cmd, "getheaders")) {
                uint8_t empty[1] = { 0 };                 /* count 0 */
                if (!send_msg(fd, cp->magic, "headers", empty, 1)) goto done;
            } else if (!strcmp(cmd, "ping")) {
                if (!send_msg(fd, cp->magic, "pong", pl, pn)) goto done;
            }

            memmove(buf, buf + c, have - (size_t)c);
            have -= (size_t)c;
        }
        if (have == sizeof buf) have = 0;                 /* a message we cannot hold */
    }
done:
    close(fd);
    return 0;
}
