/* koinu.dog - kwd, a resident outpoint-confirmation daemon
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Loads the header chain once, keeps it and the peer connection resident, and
 * answers outpoint queries over a unix socket. A cold kw outpoint reloads the
 * whole header chain per call (seconds on mainnet); kwd pays that once at
 * startup so a query fits an inline budget. One request per connection:
 *
 *   outpoint <address|spkhex> <txid:vout> <since>\n
 *
 * reply: "<rc> <text>\n", rc 0 unspent, 3 spent, 4 not seen, 1 error. */

#include "chainparams.h"
#include "base58.h"
#include "hex.h"
#include "peer.h"
#include "sync.h"
#include "headers.h"
#include "cf.h"
#include "cfstore.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stop = 0;
static void on_sig(int s) { (void)s; stop = 1; }

/* How long one client gets. The accept loop is single threaded and answers one
   request per connection, so a client that connects and says nothing holds every
   other caller behind it. Both bounds are needed: the per-read timeout catches
   silence, the deadline catches a client dribbling a byte at a time to keep
   resetting it. */
#define KWD_READ_SECONDS    5
#define KWD_REQUEST_SECONDS 10

/* What it takes to dial the peer again. A resident connection that dies leaves
   every later request answering "header sync failed" until someone restarts the
   daemon, so the parameters are kept rather than consumed at startup. */
static struct {
    const kw_chainparams *cp;
    const char *node;
    int port, tor;
} dial;

static int peer_redial(kw_peer *p)
{
    kw_peer_close(p);
    int ok = dial.tor ? kw_peer_connect_socks5(p, dial.cp, dial.node, dial.port, 15, "127.0.0.1", 9050)
                      : kw_peer_connect(p, dial.cp, dial.node, dial.port, 15);
    if (!ok) return 0;
    if (!kw_peer_handshake(p, 0)) { kw_peer_close(p); return 0; }
    fprintf(stderr, "kwd: reconnected to %s:%d\n", dial.node, dial.port);
    return 1;
}

static const kw_chainparams *chain_for(int net)
{
    if (net == 1) return &KW_DOGE_TESTNET;
    if (net == 2) return &KW_DOGE_REGTEST;
    return &KW_DOGE_MAINNET;
}

/* address or hex to scriptPubKey; returns length or 0 */
static size_t to_spk(const kw_chainparams *cp, const char *s, uint8_t out[64])
{
    uint8_t pay[64]; size_t n = 0;
    if (kw_base58check_decode(s, pay, sizeof pay, &n) && n == 21) {
        if (pay[0] == cp->p2pkh) { out[0]=0x76;out[1]=0xa9;out[2]=0x14; memcpy(out+3,pay+1,20); out[23]=0x88;out[24]=0xac; return 25; }
        if (pay[0] == cp->p2sh)  { out[0]=0xa9;out[1]=0x14; memcpy(out+2,pay+1,20); out[22]=0x87; return 23; }
        return 0;
    }
    size_t hl = strlen(s);
    if (hl >= 2 && hl <= 128 && hl % 2 == 0 && kw_hex_decode(s, hl, out, hl / 2)) return hl / 2;
    return 0;
}

static int write_all(int fd, const char *b, size_t n)
{
    while (n) { ssize_t w = write(fd, b, n); if (w <= 0) { if (w < 0 && errno == EINTR) continue; return 0; } b += w; n -= (size_t)w; }
    return 1;
}

/* Handle one request line already read into (line). Writes the reply to (fd). */
static void handle(const kw_chainparams *cp, kw_peer *p, kw_headerstore *s,
                   const char *filters_path, const char *line, int fd)
{
    char reply[256];
    char buf[512]; snprintf(buf, sizeof buf, "%s", line);
    char *cmd = strtok(buf, " \t");
    char *watch = strtok(NULL, " \t");
    char *op = strtok(NULL, " \t");
    char *sh = strtok(NULL, " \t\r\n");
    if (!cmd || strcmp(cmd, "outpoint") || !watch || !op) {
        write_all(fd, "1 bad request\n", 14); return;
    }

    uint8_t spk[64]; size_t spklen = to_spk(cp, watch, spk);
    char opbuf[128]; snprintf(opbuf, sizeof opbuf, "%s", op);
    char *ts = strtok(opbuf, ":"), *vs = strtok(NULL, ":");
    uint8_t txdisp[32], txint[32];
    if (!spklen || !ts || !vs || strlen(ts) != 64 || !kw_hex_decode(ts, 64, txdisp, 32)) {
        write_all(fd, "1 bad outpoint\n", 15); return;
    }
    for (int i = 0; i < 32; i++) txint[i] = txdisp[31 - i];
    uint32_t vout = (uint32_t)strtoul(vs, NULL, 10);
    long since = sh ? atol(sh) : 0;
    if (since < 0) since = 0;

    /* keep the resident chain current, then answer from the caches. One redial on
       failure, since the usual reason is that the peer went away. */
    long nh = kw_sync_headers(p, s, cp);
    if (nh < 0 && peer_redial(p)) nh = kw_sync_headers(p, s, cp);
    if (nh < 0) { write_all(fd, "1 header sync failed\n", 21); return; }

    kw_outpoint_result r;
    if (kw_query_outpoint_range(p, s, filters_path, 1, spk, spklen, txint, vout, (uint32_t)since, &r) != 1) {
        write_all(fd, "1 scan failed\n", 14); return;
    }
    int n;
    if (r.status == 1)      n = snprintf(reply, sizeof reply, "3 spent at height %ld depth %ld\n", r.height, r.tipheight - r.height + 1);
    else if (r.status == 0) n = snprintf(reply, sizeof reply, "0 unspent height %ld depth %ld value %llu koinu\n",
                                         r.height, r.tipheight - r.height + 1, (unsigned long long)r.value);
    else                    n = snprintf(reply, sizeof reply, "4 not seen since %ld\n", since);
    if (n > 0) write_all(fd, reply, (size_t)n);
}

int main(int argc, char **argv)
{
    int net = 0, tor = 0, port = -1;
    const char *node = NULL, *sock = NULL, *headers_path = NULL, *filters_path = NULL;
    for (int i = 1, seen = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--testnet")) net = 1;
        else if (!strcmp(argv[i], "--regtest")) net = 2;
        else if (!strcmp(argv[i], "--tor")) tor = 1;
        else if (!strcmp(argv[i], "--node")) node = (++i < argc) ? argv[i] : NULL;
        else if (!strcmp(argv[i], "--port")) port = (++i < argc) ? atoi(argv[i]) : -1;
        else if (!strcmp(argv[i], "--socket")) sock = (++i < argc) ? argv[i] : NULL;
        else if (!strcmp(argv[i], "--headers")) headers_path = (++i < argc) ? argv[i] : NULL;
        else if (!strcmp(argv[i], "--filters")) filters_path = (++i < argc) ? argv[i] : NULL;
        else if (argv[i][0] != '-' && seen++ == 0) node = argv[i];
    }
    if (!node || !sock || !filters_path) {
        fprintf(stderr, "usage: kwd [--regtest|--testnet] --node HOST [--port N] [--tor]\n"
                        "           --socket PATH --filters PATH [--headers PATH]\n");
        return 2;
    }
    const kw_chainparams *cp = chain_for(net);
    if (port < 0) port = cp->p2p_port;

    signal(SIGINT, on_sig); signal(SIGTERM, on_sig); signal(SIGPIPE, SIG_IGN);
    kw_net_verbose = 1;

    dial.cp = cp; dial.node = node; dial.port = port; dial.tor = tor;

    kw_peer p;
    int conn = tor ? kw_peer_connect_socks5(&p, cp, node, port, 15, "127.0.0.1", 9050)
                   : kw_peer_connect(&p, cp, node, port, 15);
    if (!conn) { fprintf(stderr, "kwd: connect to %s:%d failed\n", node, port); return 1; }
    if (!kw_peer_handshake(&p, 0)) { fprintf(stderr, "kwd: handshake failed\n"); kw_peer_close(&p); return 1; }

    kw_headerstore s;
    kw_headerstore_init(&s);
    if (headers_path && !kw_headerstore_load(&s, headers_path)) {
        fprintf(stderr, "kwd: header cache corrupt, starting fresh\n");
        kw_headerstore_free(&s); kw_headerstore_init(&s);
    }
    long nh = kw_sync_headers(&p, &s, cp);
    if (nh < 0) { fprintf(stderr, "kwd: header sync failed\n"); goto done; }
    if (headers_path) kw_headerstore_save(&s, headers_path);
    if (kw_cfstore_sync(&p, &s, filters_path, 1) < 0) { fprintf(stderr, "kwd: filter sync failed\n"); goto done; }

    if (strlen(sock) >= sizeof ((struct sockaddr_un *)0)->sun_path) {
        fprintf(stderr, "kwd: socket path too long (max %zu)\n", sizeof ((struct sockaddr_un *)0)->sun_path - 1); goto done;
    }
    int ls = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ls < 0) { fprintf(stderr, "kwd: socket failed\n"); goto done; }
    struct sockaddr_un sa; memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof sa.sun_path, "%s", sock);
    unlink(sock);
    /* bind creates the node at whatever the umask allows, so chmod alone leaves a
       window where any local user can connect. The umask is what closes it. */
    mode_t old_umask = umask(0177);
    int bound = bind(ls, (struct sockaddr *)&sa, sizeof sa) == 0 && listen(ls, 8) == 0;
    umask(old_umask);
    if (!bound) {
        fprintf(stderr, "kwd: bind/listen failed\n"); close(ls); goto done;
    }
    chmod(sock, 0600);                       /* belt and braces: some systems ignore the umask here */
    fprintf(stderr, "kwd: ready, tip %zu, listening on %s\n", s.count, sock);

    while (!stop) {
        int fd = accept(ls, NULL, NULL);
        if (fd < 0) { if (errno == EINTR) continue; break; }
        struct timeval tv = { KWD_READ_SECONDS, 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        struct timespec t0;
        clock_gettime(CLOCK_MONOTONIC, &t0);

        char line[512]; size_t n = 0;
        int complete = 0;
        while (n < sizeof line - 1) {
            ssize_t r = read(fd, line + n, sizeof line - 1 - n);
            if (r <= 0) break;
            n += (size_t)r;
            if (memchr(line, '\n', n)) { complete = 1; break; }
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (now.tv_sec - t0.tv_sec >= KWD_REQUEST_SECONDS) break;
        }
        line[n] = '\0';
        if (complete) handle(cp, &p, &s, filters_path, line, fd);
        else if (n) write_all(fd, "1 request truncated or too slow\n", 32);
        close(fd);
    }

    close(ls);
    unlink(sock);
done:
    kw_headerstore_free(&s);
    kw_peer_close(&p);
    return 0;
}
