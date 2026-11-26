/* koinu.dog - a tcp relay that stops mid-message on request
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * usage: stallrelay LISTEN_PORT NODE_PORT TRIGGER_FILE [once|dribble]
 *
 * Passes both directions untouched until TRIGGER_FILE appears. From then on the
 * connection open at that moment is told nothing the node says, and is sent the
 * first byte of a ping instead ("once") or the whole 32 bytes one at a time
 * ("dribble"). Later connections pass untouched, so kwd can still redial.
 *
 * In C because the suite has no interpreter but the shell, and a byte-at-a-time
 * relay in bash cannot keep up with a headers sync.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Regtest magic, the command, the length, the checksum of eight 0x01 bytes,
   then the payload. What it says does not matter: only that it never finishes. */
static const unsigned char PING[32] = {
    0xfa, 0xbf, 0xb5, 0xda,
    'p', 'i', 'n', 'g', 0, 0, 0, 0, 0, 0, 0, 0,
    0x08, 0x00, 0x00, 0x00,
    0x8d, 0x54, 0x29, 0x1b,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
};

static int listen_on(int port)
{
    struct sockaddr_in a;
    int s = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    if (s < 0) return -1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((uint16_t)port);
    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0 || listen(s, 4) < 0) {
        close(s);
        return -1;
    }
    return s;
}

static int dial(int port)
{
    struct sockaddr_in a;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((uint16_t)port);
    if (connect(s, (struct sockaddr *)&a, sizeof a) < 0) {
        close(s);
        return -1;
    }
    return s;
}

static int all(int fd, const unsigned char *p, size_t n)
{
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w <= 0) return 0;
        p += w;
        n -= (size_t)w;
    }
    return 1;
}

int main(int argc, char **argv)
{
    int lport, nport, dribble, srv, first = 1;
    const char *trigger;

    if (argc < 4) {
        fprintf(stderr, "usage: %s LISTEN_PORT NODE_PORT TRIGGER_FILE [once|dribble]\n",
                argv[0]);
        return 2;
    }
    lport = atoi(argv[1]);
    nport = atoi(argv[2]);
    trigger = argv[3];
    dribble = argc > 4 && !strcmp(argv[4], "dribble");

    signal(SIGPIPE, SIG_IGN);
    if ((srv = listen_on(lport)) < 0) {
        fprintf(stderr, "stallrelay: cannot listen on %d: %s\n", lport, strerror(errno));
        return 1;
    }
    printf("stallrelay: %d -> %d, %s\n", lport, nport, dribble ? "dribble" : "once");
    fflush(stdout);

    for (;;) {
        struct stat st;
        int kwd = accept(srv, NULL, NULL), node, mine, held = 0, sent = 0;

        if (kwd < 0) continue;
        if ((node = dial(nport)) < 0) {
            close(kwd);
            continue;
        }
        /* Only the first connection is stalled, since the redial after a drop
           has to work or this measures a dead peer rather than a slow one. */
        mine = first;
        first = 0;

        for (;;) {
            struct pollfd fd[2] = { { kwd, POLLIN, 0 }, { node, POLLIN, 0 } };
            unsigned char buf[65536];
            ssize_t r;

            if (mine && !held && stat(trigger, &st) == 0) held = 1;
            if (held) fd[1].events = 0;   /* the node backs up where it stands */

            /* Short either way. Waiting on traffic meant the trigger was not
               noticed until the next byte moved, and a kwd that has gone idle
               sends none, so nothing was ever stalled and the test passed
               against the defect it was written for. */
            if (poll(fd, 2, 200) < 0) break;

            if (held && sent < (dribble ? (int)sizeof PING : 1)) {
                if (!all(kwd, PING + sent, 1)) break;
                sent++;
                /* A tenth of a second rather than the review's ten: all 32
                   bytes must still be outstanding when kwd is next asked. */
                if (dribble) {
                    struct timespec ts = { 0, 100 * 1000 * 1000 };
                    nanosleep(&ts, NULL);
                }
            }

            if (fd[0].revents & POLLIN) {
                r = read(kwd, buf, sizeof buf);
                if (r <= 0) break;
                if (!all(node, buf, (size_t)r)) break;
            }
            if ((fd[1].revents & POLLIN) && !held) {
                r = read(node, buf, sizeof buf);
                if (r <= 0) break;
                if (!all(kwd, buf, (size_t)r)) break;
            }
        }
        close(kwd);
        close(node);
    }
}
