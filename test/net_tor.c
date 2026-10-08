/* koinu.dog - does tor really give each connection its own circuit
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Build on demand. test_socks5 proves the dialer offers RFC 1929 and that two
 * connections present different credentials, which a mock proxy can show. It
 * cannot show the thing the threat model claims: that tor keys a circuit on
 * those credentials. So this opens several connections through the real daemon
 * and asks the control port which circuit each one got.
 *
 * Needs a local tor with a ControlPort and CookieAuthFileGroupReadable, and a
 * destination its exits allow. Skips rather than fails without them. */

#include "socks5.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define CONNECTIONS 3

static const char *cookie_paths[] = {
    "/run/tor/control.authcookie",
    "/var/run/tor/control.authcookie",
    "/var/lib/tor/control_auth_cookie",
    NULL
};

static int control_open(int port)
{
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct timeval tv = { 15, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) { close(fd); return -1; }
    return fd;
}

/* Read until a line starts with "250 " or any other final reply, which is the
   control protocol's end of answer. Returns bytes held, or 0. */
static size_t control_cmd(int fd, const char *cmd, char *out, size_t outcap)
{
    size_t cl = strlen(cmd);
    if (write(fd, cmd, cl) != (ssize_t)cl || write(fd, "\r\n", 2) != 2) return 0;

    size_t held = 0;
    while (held + 1 < outcap) {
        ssize_t r = read(fd, out + held, outcap - held - 1);
        if (r <= 0) break;
        held += (size_t)r;
        out[held] = '\0';
        /* a final reply is "<code><space>", at the start of the buffer or a line */
        for (size_t i = 0; i + 4 <= held; i++) {
            if (i && out[i - 1] != '\n') continue;
            if (out[i + 3] == ' ') return held;
        }
    }
    out[held] = '\0';
    return held;
}

/* The username on the circuit record, or NULL. */
static const char *circuit_username(const char *line, char *buf, size_t cap)
{
    const char *u = strstr(line, "SOCKS_USERNAME=\"");
    if (!u) return NULL;
    u += strlen("SOCKS_USERNAME=\"");
    const char *end = strchr(u, '"');
    if (!end || (size_t)(end - u) >= cap) return NULL;
    memcpy(buf, u, (size_t)(end - u));
    buf[end - u] = '\0';
    return buf;
}

int main(int argc, char **argv)
{
    const char *dest = argc > 1 ? argv[1] : "example.com";
    int dport = argc > 2 ? atoi(argv[2]) : 80;
    int socks_port = 9050, control_port = 9051;

    char hex[256];
    size_t hexlen = 0;
    for (int i = 0; cookie_paths[i] && !hexlen; i++) {
        int fd = open(cookie_paths[i], O_RDONLY);
        if (fd < 0) continue;
        unsigned char raw[64];
        ssize_t r = read(fd, raw, sizeof raw);
        close(fd);
        if (r <= 0 || (size_t)r * 2 >= sizeof hex) continue;
        for (ssize_t k = 0; k < r; k++) snprintf(hex + k * 2, 3, "%02x", raw[k]);
        hexlen = (size_t)r * 2;
    }
    if (!hexlen) {
        printf("net_tor skipped: no readable control cookie\n");
        return 0;
    }

    int ctl = control_open(control_port);
    if (ctl < 0) { printf("net_tor skipped: no control port on %d\n", control_port); return 0; }

    char buf[65536], cmd[512];
    snprintf(cmd, sizeof cmd, "AUTHENTICATE %s", hex);
    if (!control_cmd(ctl, cmd, buf, sizeof buf) || strncmp(buf, "250", 3) != 0) {
        printf("net_tor skipped: control port refused the cookie (%.40s)\n", buf);
        close(ctl);
        return 0;
    }

    /* Circuits an earlier run left behind would otherwise count as this run's. */
    int pre[64], npre = 0;
    if (control_cmd(ctl, "GETINFO circuit-status", buf, sizeof buf)) {
        for (char *line = buf, *nl; line && *line; line = nl ? nl + 1 : NULL) {
            nl = strchr(line, '\n');
            if (nl) *nl = '\0';
            char user[64];
            if (!circuit_username(line, user, sizeof user) || npre == 64) continue;
            const char *num = line;
            while (*num && (*num < '0' || *num > '9')) num++;
            pre[npre++] = atoi(num);
        }
    }

    int fds[CONNECTIONS];
    int opened = 0;
    for (int i = 0; i < CONNECTIONS; i++) {
        fds[i] = kw_socks5_connect("127.0.0.1", socks_port, dest, dport, 30);
        if (fds[i] >= 0) opened++;
    }
    if (opened < 2) {
        printf("net_tor skipped: only %d of %d connections to %s:%d opened\n",
               opened, CONNECTIONS, dest, dport);
        for (int i = 0; i < CONNECTIONS; i++) if (fds[i] >= 0) close(fds[i]);
        close(ctl);
        return 0;
    }

    size_t n = control_cmd(ctl, "GETINFO circuit-status", buf, sizeof buf);
    for (int i = 0; i < CONNECTIONS; i++) if (fds[i] >= 0) close(fds[i]);
    close(ctl);
    if (!n) { fprintf(stderr, "FAIL: no answer to GETINFO circuit-status\n"); return 1; }

    /* Every circuit tor built for a credential pair of ours. One circuit under
       two of our credential pairs is the isolation break. The reverse is not:
       tor may build more than one circuit for a pair, conflux among them. */
    char users[64][64];
    int ids[64], found = 0;
    for (char *line = buf, *nl; line && *line; line = nl ? nl + 1 : NULL) {
        nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        char user[64];
        if (!circuit_username(line, user, sizeof user)) continue;
        const char *num = line;
        while (*num && (*num < '0' || *num > '9')) num++;         /* past "250+" */
        if (found == 64) break;
        int id = atoi(num), old = 0;
        for (int k = 0; k < npre; k++) if (pre[k] == id) old = 1;
        if (old) continue;
        snprintf(users[found], sizeof users[found], "%s", user);
        ids[found++] = id;
    }

    int distinct = 0;
    for (int i = 0; i < found; i++) {
        for (int k = 0; k < i; k++) {
            if (ids[i] == ids[k] && strcmp(users[i], users[k])) {
                fprintf(stderr, "FAIL: circuit %d serves credentials %s and %s\n",
                        ids[i], users[k], users[i]);
                return 1;
            }
        }
        int seen = 0;
        for (int k = 0; k < i; k++) if (!strcmp(users[i], users[k])) seen = 1;
        printf("  circuit %d username %s\n", ids[i], users[i]);
        if (!seen) distinct++;
    }
    if (distinct < 2) {
        fprintf(stderr, "FAIL: %d credential pairs on circuits, want at least 2\n", distinct);
        return 1;
    }

    printf("net_tor ok: %d connections, %d credential pairs, no circuit shared between two\n",
           opened, distinct);
    return 0;
}
