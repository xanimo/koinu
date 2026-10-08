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
/* (userpass) makes the proxy choose RFC 1929, as tor does when credentials are
   offered, and write the username it was given to (out) so the caller can check
   that two connections do not share one. */
static void run_proxy_auth(int ls, int grant, int domain, int userpass, int outfd)
{
    int c = accept(ls, NULL, NULL);
    if (c < 0) _exit(10);

    /* version 5, two methods: none and username/password */
    uint8_t g[4];
    if (!read_all(c, g, 4) || g[0] != 0x05 || g[1] != 0x02 ||
        g[2] != 0x00 || g[3] != 0x02) _exit(11);
    uint8_t methsel[2] = { 0x05, userpass ? 0x02 : 0x00 };
    if (write(c, methsel, 2) != 2) _exit(12);

    if (userpass) {
        uint8_t v, ul;
        if (!read_all(c, &v, 1) || v != 0x01 || !read_all(c, &ul, 1) || ul == 0) _exit(21);
        uint8_t user[256];
        if (!read_all(c, user, ul)) _exit(22);
        uint8_t pl;
        if (!read_all(c, &pl, 1) || pl == 0) _exit(23);
        uint8_t pass[256];
        if (!read_all(c, pass, pl)) _exit(24);
        if (outfd >= 0 && write(outfd, user, ul) != ul) _exit(25);
        uint8_t ok[2] = { 0x01, 0x00 };
        if (write(c, ok, 2) != 2) _exit(26);
    }

    uint8_t h[4];
    if (!read_all(c, h, 4) || h[0] != 0x05 || h[1] != 0x01 || h[2] != 0x00 || h[3] != 0x03) _exit(13);
    uint8_t hl; if (!read_all(c, &hl, 1)) _exit(14);
    uint8_t host[256]; if (!read_all(c, host, hl)) _exit(15);
    uint8_t pb[2]; if (!read_all(c, pb, 2)) _exit(16);
    if (hl != 13 || memcmp(host, "example.onion", 13) != 0) _exit(17);
    if (((pb[0] << 8) | pb[1]) != 22556) _exit(18);

    if (domain) {
        /* ATYP 0x03, a length-prefixed bound address at its legal maximum. RFC 1928
           allows this in a reply and the client discards the address, but it still
           has to read it: 255 bytes plus the port. Every reply here was ATYP 0x01
           before, so this branch had never run. */
        uint8_t reply[4 + 1 + 255 + 2];
        reply[0] = 0x05; reply[1] = grant ? 0x00 : 0x05; reply[2] = 0x00; reply[3] = 0x03;
        reply[4] = 255;
        memset(reply + 5, 'A', 255);
        reply[260] = 0x58; reply[261] = 0x0c;
        if (write(c, reply, sizeof reply) != (ssize_t)sizeof reply) _exit(19);
    } else {
        uint8_t reply[10] = { 0x05, grant ? 0x00 : 0x05, 0x00, 0x01, 0,0,0,0, 0,0 };
        if (write(c, reply, sizeof reply) != (ssize_t)sizeof reply) _exit(19);
    }

    if (grant) { uint8_t k = 'K'; if (write(c, &k, 1) != 1) _exit(20); }
    close(c);
    _exit(0);
}

static void run_proxy(int ls, int grant, int domain)
{
    run_proxy_auth(ls, grant, domain, 0, -1);
}

static int scenario(int grant, int domain, int *client_ok)
{
    int port, st;
    int ls = listen_local(&port);
    if (ls < 0) return 0;
    pid_t pid = fork();
    if (pid < 0) { close(ls); return 0; }
    if (pid == 0) { run_proxy(ls, grant, domain); }   /* never returns */
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
    if (!scenario(1, 0, &client_ok) || !client_ok) { fprintf(stderr, "FAIL: grant path\n"); return 1; }
    if (!scenario(0, 0, &client_ok) || !client_ok) { fprintf(stderr, "FAIL: refuse path\n"); return 1; }

    /* A reply carrying a domain bound address at its maximum length. The client
       discards the address but has to read it, and reading 255 bytes into a buffer
       sized for 16 is a stack overflow that no ATYP 0x01 reply can reach. */
    if (!scenario(1, 1, &client_ok) || !client_ok) { fprintf(stderr, "FAIL: domain grant path\n"); return 1; }
    if (!scenario(0, 1, &client_ok) || !client_ok) { fprintf(stderr, "FAIL: domain refuse path\n"); return 1; }

    /* Tor keys a circuit on the credentials, so two connections offering the same
       pair share an exit, and offering none shares one too: that exit sees
       plaintext p2p for every peer this wallet thinks is independent. The pair is
       random per connection, so the usernames must differ. */
    {
        uint8_t seen[2][16];
        for (int i = 0; i < 2; i++) {
            int port = 0;
            int ls = listen_local(&port);
            if (ls < 0) { fprintf(stderr, "FAIL: listen\n"); return 1; }
            int pipefd[2];
            if (pipe(pipefd) != 0) { fprintf(stderr, "FAIL: pipe\n"); return 1; }

            pid_t pid = fork();
            if (pid == 0) {
                close(pipefd[0]);
                run_proxy_auth(ls, 1, 0, 1, pipefd[1]);
                _exit(0);
            }
            close(pipefd[1]);
            int fd = kw_socks5_connect("127.0.0.1", port, "example.onion", 22556, 5);
            if (fd < 0) { fprintf(stderr, "FAIL: the username/password method was refused\n"); return 1; }
            close(fd);
            if (!read_all(pipefd[0], seen[i], sizeof seen[i])) {
                fprintf(stderr, "FAIL: no username reached the proxy\n"); return 1;
            }
            close(pipefd[0]);
            close(ls);
            int st = 0;
            waitpid(pid, &st, 0);
            if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
                fprintf(stderr, "FAIL: proxy exited %d\n", WEXITSTATUS(st)); return 1;
            }
        }
        if (memcmp(seen[0], seen[1], sizeof seen[0]) == 0) {
            fprintf(stderr, "FAIL: two connections offered the same credentials, "
                            "so tor would put them on one circuit\n");
            return 1;
        }
    }

    printf("socks5 ok: greeting, CONNECT domain/port, grant returns usable fd, refuse returns -1,\n"
           "  a 255-byte domain bound address in the reply is read without overflowing,\n"
           "  and two connections offer different credentials, so tor isolates them\n");
    return 0;
}
