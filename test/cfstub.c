/* koinu.dog - a unix socket that answers once with a canned reply
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * test/test_cfcheck.sh needs a filter source that says exactly what the test
 * wants said, including malformed things a real kwd would never send. nc can do
 * that on linux and cannot on macos, where -l -U either is not supported or
 * never binds, so the gate failed there for a reason that had nothing to do
 * with the code under test.
 *
 *     cfstub SOCKET REPLY
 *
 * Binds SOCKET, takes one connection, reads the request and discards it, writes
 * REPLY, closes, exits 0. Prints nothing on success: the test reads kw's output,
 * not this. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

int main(int argc, char **argv)
{
    if (argc != 3) { fprintf(stderr, "usage: cfstub SOCKET REPLY\n"); return 2; }
    const char *path = argv[1], *reply = argv[2];

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof sa.sun_path) {
        fprintf(stderr, "cfstub: socket path too long\n"); close(fd); return 1;
    }
    snprintf(sa.sun_path, sizeof sa.sun_path, "%s", path);
    unlink(path);
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) != 0) { perror("bind"); close(fd); return 1; }
    if (listen(fd, 1) != 0) { perror("listen"); close(fd); return 1; }

    /* The caller waits for the socket to exist before running kw, so say so as
       soon as it does rather than making the test poll the filesystem. */
    printf("ready\n");
    fflush(stdout);

    int c = accept(fd, NULL, NULL);
    if (c < 0) { perror("accept"); close(fd); return 1; }

    char req[512];
    ssize_t r = read(c, req, sizeof req);
    (void)r;                                  /* the request is not inspected */

    size_t n = strlen(reply), off = 0;
    while (off < n) {
        ssize_t w = write(c, reply + off, n - off);
        if (w <= 0) break;
        off += (size_t)w;
    }
    close(c);
    close(fd);
    unlink(path);
    return 0;
}
