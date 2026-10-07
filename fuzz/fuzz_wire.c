/* koinu.dog - fuzz harnesses that need more than a buffer
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Two targets live here rather than in fuzz_parse.c because neither is a pure
 * function of its input: the socks5 reply parser is inline in a function that
 * takes a connection, so it is driven over real loopback TCP, and kwd's request
 * parser is static, so this file includes the daemon's own source to get at it
 * byte-for-byte rather than copying the parser and testing the copy.
 *
 * Both are libFuzzer-only (make fuzz). They are out of the replay gate on
 * purpose: a TCP connect and a thread per input makes `make fuzz-run`'s 20000
 * mutations per seed a wall-clock problem, not better coverage.
 *
 * KW_FUZZ_SOCKS5 or KW_FUZZ_KWD picks the target at build time, since the kwd
 * include brings its own main. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef KW_FUZZ_SOCKS5

#include "socks5.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>

static int lfd = -1, lport;
static const uint8_t *g_reply;
static size_t g_len;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    signal(SIGPIPE, SIG_IGN);
    lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) abort();
    int on = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(lfd, (struct sockaddr *)&sa, sizeof sa) || listen(lfd, 16)) abort();
    socklen_t sl = sizeof sa;
    getsockname(lfd, (struct sockaddr *)&sa, &sl);
    lport = ntohs(sa.sin_port);
    return 0;
}

/* the proxy: whatever the fuzzer said, then half-close and drain */
static void *proxy(void *arg)
{
    (void)arg;
    int c = accept(lfd, NULL, NULL);
    if (c < 0) return NULL;
    size_t off = 0;
    while (off < g_len) {
        ssize_t w = write(c, g_reply + off, g_len - off);
        if (w <= 0) break;
        off += (size_t)w;
    }
    shutdown(c, SHUT_WR);
    char junk[512];
    while (read(c, junk, sizeof junk) > 0) { }
    close(c);
    return NULL;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* greeting 2, reply 4 + 1 + 255 + 2 is the most the client ever reads */
    if (size < 1 || size > 600) return 0;
    char host[256];
    size_t hl = 1 + (data[0] % 255);              /* the request build too */
    memset(host, 'a', hl);
    host[hl] = '\0';
    g_reply = data + 1;
    g_len = size - 1;

    pthread_t t;
    if (pthread_create(&t, NULL, proxy, NULL) != 0) return 0;
    int fd = kw_socks5_connect("127.0.0.1", lport, host, 8333, 2);
    if (fd >= 0) close(fd);
    pthread_join(t, NULL);
    return 0;
}

#endif /* KW_FUZZ_SOCKS5 */

#ifdef KW_FUZZ_KWD

/* the daemon's own parser, not a copy of it */
#define main kwd_main
#include "../cli/kwd.c"
#undef main

#include <fcntl.h>

static int devnull = -1;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (devnull < 0) devnull = open("/dev/null", O_WRONLY);
    if (size < 1) return 0;

    const kw_chainparams *cp = chain_for(data[0] % 3);
    dial.cp = cp;
    dial.nnode = 0;                               /* no peer: nothing dials out */

    /* the accept loop's framing: at most 511 bytes, NUL-terminated, and only
       handled once a newline has arrived */
    char line[512];
    size_t n = size - 1;
    if (n > sizeof line - 1) n = sizeof line - 1;
    memcpy(line, data + 1, n);
    line[n] = '\0';
    if (!memchr(line, '\n', n)) return 0;

    kw_headerstore s;
    if (!kw_headerstore_init(&s)) return 0;
    handle(cp, &s, "/nonexistent-filters", line, devnull);
    kw_headerstore_free(&s);
    return 0;
}

#endif /* KW_FUZZ_KWD */
