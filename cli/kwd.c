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
#include "cf.h"
#include "chainsel.h"

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

/* The first signal asks, the second insists. Startup syncs the headers and the
   filters before it ever reaches the accept loop, and neither of those looks at
   (stop), so a kill during startup was noted and then ignored for as long as the
   sync took. test_kwd left twenty-five daemons running on this machine that way,
   each one outliving the directory it was given. */
static void on_sig(int s)
{
    (void)s;
    if (stop) _exit(1);
    stop = 1;
}

/* How long one client gets. The accept loop is single threaded and answers one
   request per connection, so a client that connects and says nothing holds every
   other caller behind it. Both bounds are needed: the per-read timeout catches
   silence, the deadline catches a client dribbling a byte at a time to keep
   resetting it. */
#define KWD_READ_SECONDS    5
#define KWD_REQUEST_SECONDS 10

/* Resident connections, one per --node. Every request weighs the chains they serve
   and keeps the heaviest, so a peer withholding a confirmation has to be agreed
   with by all of them rather than believed on its own. One --node is the old
   behaviour and compares nothing.

   The parameters are kept rather than consumed at startup because a connection
   that dies would otherwise leave every later request answering "header sync
   failed" until someone restarted the daemon. */
#define KWD_MAX_PEERS 3

static struct {
    const kw_chainparams *cp;
    const char *node[KWD_MAX_PEERS];
    int nnode;
    int port, tor;
} dial;

static int peer_dial(kw_peer *p, const char *host)
{
    int ok = dial.tor ? kw_peer_connect_socks5(p, dial.cp, host, dial.port, 15, "127.0.0.1", 9050)
                      : kw_peer_connect(p, dial.cp, host, dial.port, 15);
    if (!ok) return 0;
    if (!kw_peer_handshake(p, 0)) { kw_peer_close(p); return 0; }
    return 1;
}

static kw_peer g_peer[KWD_MAX_PEERS];
static int     g_alive[KWD_MAX_PEERS];
static int     g_filters;            /* the peers serve bip158 and the cache is built */

/* The first connection still standing, which is what the filter and block queries
   use. They need a peer, not a particular one. */
static kw_peer *first_live(void)
{
    for (int i = 0; i < dial.nnode; i++) if (g_alive[i]) return &g_peer[i];
    return NULL;
}

/* Every live peer's chain, weighed, with the work of everything above the newest
   anchor checked. Anything that dropped since the last request is dialled again
   first. Returns headers appended, or -1 when no peer served a chain that
   verified.

   The work check is the point: until this, kwd answered whether an outpoint was
   confirmed without checking that the chain it answered from had any work behind
   it, which is the one question a payment backend exists to answer. */
static long kwd_sync(kw_headerstore *s, const kw_chainparams *cp)
{
    uint32_t pow_from = 1;
    if (cp->ncheckpoints) pow_from = cp->checkpoints[cp->ncheckpoints - 1].height + 1;

    kw_peer *live[KWD_MAX_PEERS];
    int n = 0;
    for (int i = 0; i < dial.nnode; i++) {
        if (!g_alive[i]) {
            if (!peer_dial(&g_peer[i], dial.node[i])) continue;
            g_alive[i] = 1;
            fprintf(stderr, "kwd: connected to %s:%d\n", dial.node[i], dial.port);
        }
        live[n++] = &g_peer[i];
    }
    if (!n) return -1;

    kw_chainsel_result r;
    long nh = kw_sync_headers_best(live, n, s, cp, pow_from, &r);
    if (r.bad_height)
        fprintf(stderr, "kwd: header %u does not prove its work; that chain was not "
                        "used\n", r.bad_height);
    if (nh < 0) {
        /* whatever went wrong, the connections are suspect: dial again next time */
        for (int i = 0; i < dial.nnode; i++) { if (g_alive[i]) kw_peer_close(&g_peer[i]); g_alive[i] = 0; }
        return -1;
    }
    if (kw_net_verbose)
        fprintf(stderr, "kwd: %llu header(s) work-checked from %u, %d of %d peers "
                        "served a chain\n",
                (unsigned long long)r.pow_checked, pow_from, r.ncandidates, n);
    return nh;
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
static void handle(const kw_chainparams *cp, kw_headerstore *s,
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

    /* keep the resident chain current, then answer from the caches */
    long nh = kwd_sync(s, cp);
    if (nh < 0) { write_all(fd, "1 header sync failed\n", 21); return; }
    kw_peer *p = first_live();
    if (!p) { write_all(fd, "1 no peer\n", 10); return; }

    /* Without filters the range is fetched whole. kw_query_outpoint_range refuses
       a span past KW_CF_MAX_UNFILTERED_SPAN, which is what stops a local client
       tying up this single-threaded loop for millions of round trips: the request
       deadline covers reading the line, not the work behind it. */
    kw_outpoint_result r;
    if (kw_query_outpoint_range(p, s, g_filters ? filters_path : NULL, 1,
                                spk, spklen, txint, vout, (uint32_t)since, &r) != 1) {
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
    int net = 0, tor = 0, port = -1, nnode = 0;
    const char *node[KWD_MAX_PEERS] = { 0 };
    const char *sock = NULL, *headers_path = NULL, *filters_path = NULL;
    for (int i = 1, seen = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--testnet")) net = 1;
        else if (!strcmp(argv[i], "--regtest")) net = 2;
        else if (!strcmp(argv[i], "--tor")) tor = 1;
        else if (!strcmp(argv[i], "--node")) {
            const char *v = (++i < argc) ? argv[i] : NULL;
            /* more than three is refused rather than dropped: a daemon quietly
               weighing fewer chains than it was given is the wrong failure */
            if (v && nnode == KWD_MAX_PEERS) {
                fprintf(stderr, "kwd: at most %d --node\n", KWD_MAX_PEERS);
                return 2;
            }
            if (v) node[nnode++] = v;
        }
        else if (!strcmp(argv[i], "--port")) {
            const char *v = (++i < argc) ? argv[i] : NULL;
            char *end = NULL;
            long n = v ? strtol(v, &end, 10) : -1;
            if (!v || end == v || *end || n < 1 || n > 65535) {
                fprintf(stderr, "kwd: --port wants 1..65535\n"); return 2;
            }
            port = (int)n;
        }
        else if (!strcmp(argv[i], "--socket")) sock = (++i < argc) ? argv[i] : NULL;
        else if (!strcmp(argv[i], "--headers")) headers_path = (++i < argc) ? argv[i] : NULL;
        else if (!strcmp(argv[i], "--filters")) filters_path = (++i < argc) ? argv[i] : NULL;
        else if (argv[i][0] != '-' && seen++ == 0 && nnode < KWD_MAX_PEERS) node[nnode++] = argv[i];
    }
    if (!nnode || !sock || !filters_path) {
        fprintf(stderr, "usage: kwd [--regtest|--testnet] --node HOST [--node HOST ...]\n"
                        "           [--port N] [--tor] --socket PATH --filters PATH\n"
                        "           [--headers PATH]\n"
                        "\n"
                        "Several --node weigh the chains they serve and keep the one with\n"
                        "the most work. One compares nothing.\n");
        return 2;
    }
    const kw_chainparams *cp = chain_for(net);
    if (port < 0) port = cp->p2p_port;

    signal(SIGINT, on_sig); signal(SIGTERM, on_sig); signal(SIGPIPE, SIG_IGN);
    kw_net_verbose = 1;

    dial.cp = cp; dial.port = port; dial.tor = tor; dial.nnode = nnode;
    for (int i = 0; i < nnode; i++) dial.node[i] = node[i];

    /* One has to answer; the rest are optional, since a peer being down is not a
       reason to refuse to run, only a reason to compare fewer chains. */
    int up = 0;
    for (int i = 0; i < nnode; i++) {
        if (peer_dial(&g_peer[i], node[i])) { g_alive[i] = 1; up++; }
        else fprintf(stderr, "kwd: connect to %s:%d failed\n", node[i], port);
    }
    if (!up) { fprintf(stderr, "kwd: no peer answered\n"); return 1; }
    if (nnode == 1)
        fprintf(stderr, "kwd: one peer, so nothing compares its chain against "
                        "another's by work\n");

    kw_headerstore s;
    kw_headerstore_init(&s);
    if (headers_path && !kw_headerstore_load(&s, headers_path)) {
        fprintf(stderr, "kwd: header cache corrupt, starting fresh\n");
        kw_headerstore_free(&s); kw_headerstore_init(&s);
    }
    long nh = kwd_sync(&s, cp);
    if (stop) goto done;
    if (nh < 0) { fprintf(stderr, "kwd: header sync failed\n"); goto done; }
    if (headers_path) kw_headerstore_save(&s, headers_path);
    {
        /* Filters make a query cost the blocks that match rather than the blocks
           in the range. No peer on the public network serves them, so refusing to
           start without them meant refusing to start at all. Runs either way and
           says which. */
        kw_peer *fp = first_live();
        if (!fp) { fprintf(stderr, "kwd: no peer\n"); goto done; }
        if (fp->peer_services && !(fp->peer_services & KW_NODE_COMPACT_FILTERS)) {
            fprintf(stderr, "kwd: peer serves no compact filters, answering from blocks; "
                            "a request costs every block since its --since\n");
        } else if (kw_cfstore_sync(fp, &s, filters_path, 1) < 0) {
            fprintf(stderr, "kwd: filter sync failed\n"); goto done;
        } else {
            g_filters = 1;
        }
        if (stop) goto done;
    }

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
        if (complete) handle(cp, &s, filters_path, line, fd);
        else if (n) write_all(fd, "1 request truncated or too slow\n", 32);
        close(fd);
    }

    close(ls);
    unlink(sock);
done:
    kw_headerstore_free(&s);
    for (int i = 0; i < dial.nnode; i++) if (g_alive[i]) kw_peer_close(&g_peer[i]);
    return 0;
}
