/* netfuzz target 6: kwd's request path end to end. cli/kwd.c is #included
   unmodified (main renamed), its resident peers are replaced by socketpair fake
   peers placed in g_peer/g_alive, and handle() is called for 1-3 fuzzed or
   well-formed request lines against one resident header store, so a request
   reaches kwd_sync -> kw_sync_headers_best and kw_query_outpoint_range.
   A redial after a failure targets 127.0.0.1:1, which refuses at once.

   input: [cfg][pre][chain...][req0 sel][peer scripts...][more req sels]
   cfg: bits0-1 npeers-1, bit2 filters (cache pre-built for the preloaded prefix)

   K1 a "0 unspent" or "3 spent" reply names a height inside the store whose
      header is the one the served chain's block came from, and an unspent value
      equals that block's output value at the outpoint
   K2 when a request is answered from the store (rc 0/3/4), every header in it
      meets its target (regtest has no anchors, so pow_from is 1): finding 11,
      reported once and then disabled
   K3 the reply is one line beginning with a known rc */
#define main kwd_main
#include "../../cli/kwd.c"
#undef main
#include "script.h"
#include "blocks.h"

static const kw_chainparams *CPK = &KW_DOGE_REGTEST;
static char fpath[4096];
static int known11, known1;

/* a loopback listener so a redial after a failure reaches a scripted peer */
#include <netinet/in.h>
#include <arpa/inet.h>
static int lsock = -1, lport;
static nf_buf redial;                      /* bytes every redialled connection gets */
static pthread_mutex_t rmx = PTHREAD_MUTEX_INITIALIZER;
static void *conn_main(void *a)
{
    nf_peer *pp = (nf_peer *)a;
    nf_peer_main(pp);
    close(pp->fd); nb_free(&pp->script); free(pp);
    return NULL;
}
static void *listen_main(void *a)
{
    (void)a;
    for (;;) {
        int fd = accept(lsock, NULL, NULL);
        if (fd < 0) continue;
        nf_peer *pp = (nf_peer *)calloc(1, sizeof *pp);
        pp->fd = fd;
        pthread_mutex_lock(&rmx);
        nb_put(&pp->script, redial.b, redial.n);
        pthread_mutex_unlock(&rmx);
        pthread_t t;
        if (pthread_create(&t, NULL, conn_main, pp) == 0) pthread_detach(t);
        else { close(fd); nb_free(&pp->script); free(pp); }
    }
    return NULL;
}
static void start_listener(void)
{
    lsock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET; sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK); sa.sin_port = 0;
    if (bind(lsock, (struct sockaddr *)&sa, sizeof sa) || listen(lsock, 64)) abort();
    socklen_t sl = sizeof sa; getsockname(lsock, (struct sockaddr *)&sa, &sl);
    lport = ntohs(sa.sin_port);
    pthread_t t; pthread_create(&t, NULL, listen_main, NULL); pthread_detach(t);
}
static void version_frame(nf_buf *out)
{
    nf_buf b = {0};
    nb_le32(&b, 70015); nb_le64(&b, 0); nb_le64(&b, 0);
    for (int i = 0; i < 52; i++) nb_u8(&b, 0);
    nb_le64(&b, 1); nb_u8(&b, 0); nb_le32(&b, 0); nb_u8(&b, 0);
    nf_frame(out, KW_DOGE_REGTEST.magic, "version", b.b, b.n, 1, 0, 0);
    nf_frame(out, KW_DOGE_REGTEST.magic, "verack", NULL, 0, 1, 0, 0);
    nb_free(&b);
}

static uint8_t badraw[NB_MAXB][80];
struct kctx { nb_chain *c; int hcur; int bcur, fcur; uint8_t cur[32]; uint32_t h; };

static int st_k(void *v, nf_in *in, nf_peer *pp, int op)
{
    struct kctx *x = (struct kctx *)v;
    nb_chain *c = x->c;
    nf_buf pl = {0};
    uint8_t sel = in8(in);
    switch (op & 3) {
    case 1:
        if (!(sel & 0x80)) {                  /* the next honest headers of the served chain */
            int n = 1 + sel % 4; if (x->hcur + n > c->nb) n = c->nb - x->hcur;
            if (n < 0) n = 0;
            nb_varint(&pl, (uint64_t)n);
            for (int i = 0; i < n; i++) { nb_put(&pl, c->hdr[x->hcur + i].raw, 80); nb_u8(&pl, 0); }
            if (n) { memcpy(x->cur, c->hdr[x->hcur + n - 1].hash, 32); x->h = (uint32_t)(x->hcur + n); }
            x->hcur += n;
        } else if ((sel & 0x40) && x->hcur < c->nb) {   /* block hcur's header with failing work */
            nb_varint(&pl, 1); nb_put(&pl, badraw[x->hcur], 80); nb_u8(&pl, 0);
            kw_hash256(badraw[x->hcur], 80, x->cur); x->h = (uint32_t)x->hcur + 1;
        } else {                              /* fuzzed headers on top of where we are */
            uint8_t tip[32];
            size_t n = nf_headers_msg(in, &pl, x->cur, x->h, 6, tip, CPK->genesis_time);
            memcpy(x->cur, tip, 32); x->h += (uint32_t)n;
        }
        nf_frame(&pp->script, CPK->magic, "headers", pl.b, pl.n, 1, 0, 0);
        break;
    case 2:
        if (sel & 1) {                        /* full chain from genesis: what a fork_point asks */
            nb_varint(&pl, (uint64_t)c->nb);
            for (int i = 0; i < c->nb; i++) { nb_put(&pl, c->hdr[i].raw, 80); nb_u8(&pl, 0); }
        } else nb_u8(&pl, 0);
        nf_frame(&pp->script, CPK->magic, "headers", pl.b, pl.n, 1, 0, 0);
        break;
    case 3: {
        uint8_t m = in8(in); if (m & 0x80) m = 0;
        int k = (sel >> 6) & 3;
        if (k == 3) {                         /* the body behind a bad-work header */
            int b = (sel & 0x1f) % c->nb;
            nf_buf x2 = {0}; nb_put(&x2, c->body[b].b, c->body[b].n); memcpy(x2.b, badraw[b], 80);
            nf_frame(&pp->script, CPK->magic, "block", x2.b, x2.n, 1, 0, 0); nb_free(&x2);
        } else if (k == 0) nb_serve_block(&pp->script, CPK->magic, c, (sel & 0x20) ? x->bcur++ % c->nb : (sel & 0x1f) % c->nb, m, in);
        else if (k == 1) nb_serve_cfheaders(&pp->script, CPK->magic, c, (sel & 0x1f) % c->nb, c->nb, m, in);
        else nb_serve_cfilter(&pp->script, CPK->magic, c, (sel & 0x20) ? x->fcur++ % c->nb : (sel & 0x1f) % c->nb, m, in);
        break; }
    }
    nb_free(&pl);
    return 1;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    nf_genesis(CPK, nf_gen);
    nb_mine_headers = 1;
    if (getenv("NF_VERBOSE")) kw_net_verbose = 1;
    const char *d = getenv("FZ_TMP");
    snprintf(fpath, sizeof fpath, "%s/kwd-%d.cf", d ? d : "/tmp", (int)getpid());
    signal(SIGPIPE, SIG_IGN);
    start_listener();
    return 0;
}

static void make_line(nf_in *in, const nb_chain *c, char *line, size_t cap)
{
    uint8_t sel = in8(in);
    if (sel & 0x80) {                         /* raw line */
        size_t g; const uint8_t *b = intake(in, in8(in) % 120, &g);
        size_t n = g < cap - 2 ? g : cap - 2;
        memcpy(line, b, n); line[n] = '\n'; line[n + 1] = 0;
        return;
    }
    char tx[65]; nf_hex_rev(c->ttxid, tx);
    char spk[81]; static const char d[] = "0123456789abcdef";
    const uint8_t *w = (sel & 1) ? NB_SPK_B : NB_SPK_A;
    for (int i = 0; i < 25; i++) { spk[2 * i] = d[w[i] >> 4]; spk[2 * i + 1] = d[w[i] & 15]; }
    spk[50] = 0;
    uint32_t vout = (sel & 2) ? in8(in) % 4 : c->tvout;
    long since = (sel & 4) ? (long)(in8(in) % 12) - 1 : 0;
    if (sel & 8) snprintf(line, cap, "outpoint %s %s:%u\n", spk, tx, vout);
    else snprintf(line, cap, "outpoint %s %s:%u %ld\n", spk, tx, vout, since);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 4) return 0;
    nf_in in = { data, size };
    uint8_t cfg = in8(&in), pre = in8(&in);
    int npeers = (cfg & 3) == 3 ? 1 : (cfg & 3) + 1;
    nb_chain *c = (nb_chain *)calloc(1, sizeof *c);
    nb_build(c, &in, nf_gen, CPK->genesis_time);
    int k = pre % (c->nb + 1);
    for (int b = 0; b < c->nb; b++) {
        memcpy(badraw[b], c->hdr[b].raw, 80);
        badraw[b][79] ^= 0x40;
        nf_mine_cached(badraw[b], 0);
    }

    kw_headerstore s; kw_headerstore_init(&s);
    for (int b = 0; b < k; b++) kw_headerstore_append(&s, &c->hdr[b]);
    g_filters = (cfg & 4) && k > 0;
    if (g_filters) nb_write_cache(c, fpath, k);

    char lines[3][256];
    make_line(&in, c, lines[0], sizeof lines[0]);

    nf_peer pp[KWD_MAX_PEERS]; struct kctx kc[KWD_MAX_PEERS];
    memset(pp, 0, sizeof pp);
    static const char *const loop[KWD_MAX_PEERS] = { "127.0.0.1", "127.0.0.1", "127.0.0.1" };
    dial.cp = CPK; dial.nnode = npeers; dial.port = lport; dial.tor = 0;
    for (int i = 0; i < npeers; i++) {
        dial.node[i] = loop[i];
        nf_peer_open(&pp[i], &g_peer[i], CPK);
        g_alive[i] = 1;
        memset(&kc[i], 0, sizeof kc[i]); kc[i].c = c; kc[i].hcur = k;
        memcpy(kc[i].cur, k ? c->hdr[k - 1].hash : nf_gen, 32); kc[i].h = (uint32_t)k;
        nf_script(&in, &pp[i], CPK->magic, 32, st_k, &kc[i]);
    }
    /* the redial peer: handshake, then its own script */
    {
        nf_peer tmp; memset(&tmp, 0, sizeof tmp);
        version_frame(&tmp.script);
        struct kctx rk; memset(&rk, 0, sizeof rk); rk.c = c; rk.hcur = k;
        memcpy(rk.cur, k ? c->hdr[k - 1].hash : nf_gen, 32); rk.h = (uint32_t)k;
        nf_script(&in, &tmp, CPK->magic, 24, st_k, &rk);
        pthread_mutex_lock(&rmx); redial.n = 0; nb_put(&redial, tmp.script.b, tmp.script.n); pthread_mutex_unlock(&rmx);
        nb_free(&tmp.script); free(tmp.cuts);
    }
    int nreq = 1 + in8(&in) % 3;
    for (int r = 1; r < nreq; r++) make_line(&in, c, lines[r], sizeof lines[r]);
    for (int i = 0; i < npeers; i++) nf_peer_start(&pp[i]);

    for (int r = 0; r < nreq; r++) {
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) break;
        handle(CPK, &s, fpath, lines[r], sv[0]);
        close(sv[0]);
        char rep[512]; ssize_t rn = read(sv[1], rep, sizeof rep - 1);
        close(sv[1]);
        if (rn <= 0) NF_FAIL("K3 no reply to request %d", r);
        rep[rn] = 0;
        if (getenv("NF_DEBUG")) fprintf(stderr, "req %d: %s -> %s", r, lines[r], rep);
        char *nl = strchr(rep, '\n');
        if (!nl || nl[1] != 0 || !strchr("0134", rep[0]) || rep[1] != ' ') NF_FAIL("K3 reply not one line: %s", rep);
        int rc = rep[0] - '0';
        if (rc == 0 || rc == 3 || rc == 4) {
            for (size_t i = 0; i < s.count; i++)
                if (!nf_pow_ok_cached(s.h[i].raw)) {
                    nf_known("finding 11: kwd answered from a store holding an unchecked header", &known11);
                    break;
                }
        }
        if (rc == 0 || rc == 3) {
            long H = 0, D = 0; unsigned long long V = 0;
            if (rc == 0 && sscanf(rep, "0 unspent height %ld depth %ld value %llu", &H, &D, &V) != 3) NF_FAIL("K3 unparsable %s", rep);
            if (rc == 3 && sscanf(rep, "3 spent at height %ld depth %ld", &H, &D) != 2) NF_FAIL("K3 unparsable %s", rep);
            if (H < 1 || (size_t)H > s.count) NF_FAIL("K1 height %ld outside the store (%zu)", H, s.count);
            uint8_t bh[32]; if (H <= c->nb) kw_hash256(badraw[H - 1], 80, bh);
            if (H <= c->nb && memcmp(s.h[H - 1].hash, c->hdr[H - 1].hash, 32) && !memcmp(s.h[H - 1].hash, bh, 32))
                nf_known("finding 11: kwd answered from a bad-work header with a valid body", &known11);
            else if (H > c->nb || memcmp(s.h[H - 1].hash, c->hdr[H - 1].hash, 32))
                NF_FAIL("K1 answered at height %ld from a header that is not the served block's", H);
            if (D != (long)s.count - H + 1) NF_FAIL("K1 depth %ld for height %ld tip %zu", D, H, s.count);
            if (rc == 0) {
                int b = (int)H - 1, ok = 0, pays = 0;
                char tx[65]; nf_hex_rev(c->ttxid, tx);
                for (int t = 0; t < c->ntx[b]; t++)
                    if (!memcmp(c->txid[b][t], c->ttxid, 32) && (int)c->tvout < c->nout[b][t] && c->val[b][t][c->tvout] == V) {
                        ok = 1; pays |= c->spklen[b][t][c->tvout] == 25 &&
                            (!memcmp(c->spk[b][t][c->tvout], NB_SPK_A, 25) || !memcmp(c->spk[b][t][c->tvout], NB_SPK_B, 25));
                    }
                if (!ok && strstr(lines[r], tx)) {
                    /* the request may have named another vout; only check the target's */
                    unsigned vo = 0; const char *colon = strchr(strstr(lines[r], tx), ':');
                    if (colon && sscanf(colon + 1, "%u", &vo) == 1 && vo == c->tvout)
                        NF_FAIL("K1 value %llu at %ld is not the block's output", V, H);
                }
                if (ok && !pays) nf_known("finding 1: kwd reported an output paying another script", &known1);
            }
        }
    }

    for (int i = 0; i < npeers; i++) {
        if (g_alive[i]) kw_peer_close(&g_peer[i]);
        g_alive[i] = 0;
        nf_peer_finish(&pp[i]);
    }
    kw_headerstore_free(&s);
    nb_free_chain(c); free(c);
    return 0;
}
