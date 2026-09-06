/* koinu.dog - SOCKS5 dialer tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * A forked mock proxy validates the greeting and the CONNECT request (domain
 * name and port), then either grants or refuses. The parent drives the real
 * kw_socks5_connect against it over loopback. */

#include "socks5.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static int read_all(int fd, uint8_t *b, size_t n)
{
    while (n) { ssize_t r = read(fd, b, n); if (r <= 0) return 0; b += r; n -= (size_t)r; }
    return 1;
}

/* Start a loopback listener, return its fd and set *port. */
static int listen_local(int *port)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    int on = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET; sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK); sa.sin_port = 0;
    if (bind(s, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(s, 1) != 0) { close(s); return -1; }
    socklen_t sl = sizeof sa;
    if (getsockname(s, (struct sockaddr *)&sa, &sl) != 0) { close(s); return -1; }
    *port = ntohs(sa.sin_port);
    return s;
}

/* The mock proxy. (grant) chooses whether it replies success or refused.
   Exits 0 if the client's handshake was exactly right, nonzero otherwise. */
static void run_proxy(int ls, int grant)
{
    int c = accept(ls, NULL, NULL);
    if (c < 0) _exit(10);

    uint8_t g[3];
    if (!read_all(c, g, 3) || g[0] != 0x05 || g[1] != 0x01 || g[2] != 0x00) _exit(11);
    uint8_t methsel[2] = { 0x05, 0x00 };
    if (write(c, methsel, 2) != 2) _exit(12);

    uint8_t h[4];
    if (!read_all(c, h, 4) || h[0] != 0x05 || h[1] != 0x01 || h[2] != 0x00 || h[3] != 0x03) _exit(13);
    uint8_t hl; if (!read_all(c, &hl, 1)) _exit(14);
    uint8_t host[256]; if (!read_all(c, host, hl)) _exit(15);
    uint8_t pb[2]; if (!read_all(c, pb, 2)) _exit(16);
    if (hl != 13 || memcmp(host, "example.onion", 13) != 0) _exit(17);
    if (((pb[0] << 8) | pb[1]) != 22556) _exit(18);

    uint8_t reply[10] = { 0x05, grant ? 0x00 : 0x05, 0x00, 0x01, 0,0,0,0, 0,0 };
    if (write(c, reply, sizeof reply) != (ssize_t)sizeof reply) _exit(19);

    if (grant) { uint8_t k = 'K'; if (write(c, &k, 1) != 1) _exit(20); }
    close(c);
    _exit(0);
}

static int scenario(int grant, int *client_ok)
{
    int port, st;
    int ls = listen_local(&port);
    if (ls < 0) return 0;
    pid_t pid = fork();
    if (pid < 0) { close(ls); return 0; }
    if (pid == 0) { run_proxy(ls, grant); }   /* never returns */
    close(ls);

    int fd = kw_socks5_connect("127.0.0.1", port, "example.onion", 22556, 5);
    *client_ok = 0;
    if (grant) {
        if (fd >= 0) { uint8_t b = 0; if (read_all(fd, &b, 1) && b == 'K') *client_ok = 1; }
    } else {
        if (fd < 0) *client_ok = 1;
    }
    if (fd >= 0) close(fd);
    waitpid(pid, &st, 0);
    return WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);

    int client_ok;
    if (!scenario(1, &client_ok) || !client_ok) { fprintf(stderr, "FAIL: grant path\n"); return 1; }
    if (!scenario(0, &client_ok) || !client_ok) { fprintf(stderr, "FAIL: refuse path\n"); return 1; }

    printf("socks5 ok: greeting, CONNECT domain/port, grant returns usable fd, refuse returns -1\n");
    return 0;
}
