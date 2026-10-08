/* netfuzz target 8: kw_psync_headers, the parallel checkpointed fill, against a
   loopback node whose every connection follows a fuzzed misbehaviour tape and
   turns honest when its tape runs out (so a fill always can finish: the 300 s
   stall rule is the only way out otherwise, and that is documented behaviour).

   input: [cfg][ntapes][tape0 len][tape0 ops]...
   cfg: bits0-1 workers (1..4), bits2-3 hosts named (1..4, same listener),
        bits4-5 checkpoint layout (every 10, every 7 + 40, every 1 up to 8 then 40, 0/40)

   F1 r == 40: the cache loads (kw_headerstore_load), holds 40 headers and every
      one is the honest header at that height; no .part is left
   F2 r == -1: neither the cache nor the .part exists
   F3 r is never 0 (the cache never pre-exists here) */
#include "script.h"
#include "psync.h"
#include "msg.h"
#include "../../test/psyncnode.h"
#include <signal.h>

#define PN 40
static kw_block_header ch[PN], forged[PN];
static uint8_t anch[32];
static char hexes[PN + 1][65];
static kw_checkpoint cps[PN + 1];
static kw_chainparams pcp;
static kw_testnode dummy;               /* only for kwtn_height_of */
static int ls = -1; static uint16_t port;
static char cpath[4096];

#define MAXT 16
#define TAPE 24
static uint8_t tapes[MAXT][TAPE]; static int tlen[MAXT], ntapes;
static int conn_no;
static pthread_mutex_t tm = PTHREAD_MUTEX_INITIALIZER;
static volatile int live_conns;

struct conn { int fd; uint8_t tape[TAPE]; int tn, tp; };

static int frame_send(int fd, const char *cmd, const uint8_t *pl, size_t pn) { return kwtn_send(fd, pcp.magic, cmd, pl, pn); }

static int send_hdrs(int fd, const kw_block_header *src, int from, int count, int flip, int fpos)
{
    if (count < 0) count = 0;
    if (from + count > PN) count = PN - from;
    if (count < 0) count = 0;
    uint8_t *b = (uint8_t *)malloc(9 + (size_t)(count ? count : 1) * 81); size_t k = 0;
    b[k++] = (uint8_t)count;
    for (int i = 0; i < count; i++) {
        memcpy(b + k, src[from + i].raw, 80);
        if (flip && i == fpos % count) b[k + (flip % 80)] ^= 0x01;
        k += 80; b[k++] = 0;
    }
    int ok = frame_send(fd, "headers", b, k);
    free(b);
    return ok;
}

static int reply(struct conn *c, const uint8_t *pl, size_t pn)
{
    if (pn < 5) return 0;
    size_t off = 4; uint64_t nloc = pl[off++];
    if (nloc > 64 || off + nloc * 32 + 32 > pn) return 0;
    int from = -1;
    for (uint64_t i = 0; i < nloc && from < 0; i++) {
        if (!memcmp(pl + off + i * 32, anch, 32)) from = 0;
        else { int h = kwtn_height_of(&dummy, pl + off + i * 32); if (h) from = h; }
    }
    if (from < 0) from = 0;
    off += nloc * 32;
    int stop = PN; { int s = kwtn_height_of(&dummy, pl + off); if (s) stop = s; }
    uint8_t op = c->tp < c->tn ? c->tape[c->tp++] : 0xf0;      /* exhausted: honest, big batch */
    uint8_t arg = c->tp < c->tn ? c->tape[c->tp++] : 0;
    int batch = 1 + (op >> 4);
    if (op == 0xf0) batch = PN;
    int honest_n = stop - from < batch ? stop - from : batch;
    switch (op & 15) {
    default: return send_hdrs(c->fd, ch, from, honest_n, 0, 0);
    case 1: return send_hdrs(c->fd, ch, from, honest_n, 1 + arg, arg >> 3);
    case 2: {                                   /* a self-consistent fork from the locator */
        kw_block_header f[PN]; uint8_t prev[32];
        memcpy(prev, from ? ch[from - 1].hash : anch, 32);
        int n = honest_n;
        for (int i = 0; i < n; i++) {
            uint8_t raw[80]; memcpy(raw, ch[from + i].raw, 80); memcpy(raw + 4, prev, 32); raw[40] ^= (uint8_t)(1 + arg);
            kw_block_header_parse(raw, 80, &f[i]); memcpy(prev, f[i].hash, 32);
        }
        uint8_t *b = (uint8_t *)malloc(9 + (size_t)(n ? n : 1) * 81); size_t k = 0; b[k++] = (uint8_t)n;
        for (int i = 0; i < n; i++) { memcpy(b + k, f[i].raw, 80); k += 80; b[k++] = 0; }
        int ok = frame_send(c->fd, "headers", b, k); free(b); return ok; }
    case 3: { uint8_t z = 0; return frame_send(c->fd, "headers", &z, 1); }
    case 4: { uint8_t n8[8] = {0}; for (int i = 0; i < (arg & 7); i++) frame_send(c->fd, "ping", n8, 8);
              return send_hdrs(c->fd, ch, from, honest_n, 0, 0); }
    case 5: { uint8_t fr[30] = {0}; for (int i = 0; i < 4; i++) fr[i] = (uint8_t)(pcp.magic >> (8 * i));
              memcpy(fr + 4, "headers", 7); fr[16] = 6; fr[20] = arg; return kwtn_write_all(c->fd, fr, 30); }
    case 6: return 0;
    case 7: return send_hdrs(c->fd, ch, from + 1 + (arg & 3), honest_n, 0, 0);
    case 8: return send_hdrs(c->fd, ch, from, batch + (arg & 15), 0, 0);  /* past the stop */
    case 9: return send_hdrs(c->fd, ch, arg % PN, honest_n, 0, 0);
    case 10: { uint8_t inv[37] = {1, 2}; frame_send(c->fd, "inv", inv, 37); return send_hdrs(c->fd, ch, from, honest_n, 0, 0); }
    case 11: send_hdrs(c->fd, ch, from, honest_n, 0, 0); return send_hdrs(c->fd, ch, from, honest_n, 0, 0);
    case 12: { uint8_t b[90] = {0}; b[0] = (uint8_t)(1 + (arg & 3)); memcpy(b + 1, ch[from < PN ? from : 0].raw, 80);
               return frame_send(c->fd, "headers", b, 1 + (arg % 89)); }
    case 13: { uint8_t f8[8] = {0}; f8[7] = arg & 0x7f; frame_send(c->fd, "feefilter", f8, 8);
               return send_hdrs(c->fd, ch, from, honest_n, 0, 0); }
    case 14: return send_hdrs(c->fd, forged, from, honest_n, 0, 0);   /* a parallel chain off the same anchor */
    }
}

static void *serve(void *a)
{
    struct conn *c = (struct conn *)a;
    uint8_t buf[65536]; size_t have = 0;
    if (c->tn && (c->tape[0] & 15) == 6 && (c->tape[0] >> 4) == 0) goto done;   /* refuse the handshake */
    for (;;) {
        ssize_t r = read(c->fd, buf + have, sizeof buf - have);
        if (r <= 0) break;
        have += (size_t)r;
        for (;;) {
            char cmd[13]; const uint8_t *pl = NULL; size_t pn = 0;
            int used = kw_msg_parse(pcp.magic, buf, have, cmd, &pl, &pn);
            if (used <= 0) { if (used < 0) goto done; break; }
            if (!strcmp(cmd, "version")) {
                kw_msg_version v; memset(&v, 0, sizeof v);
                v.version = KW_PROTOCOL_VERSION; v.timestamp = 1700000000;
                kw_netaddr_ipv4(v.recv_ip, 127, 0, 0, 1); kw_netaddr_ipv4(v.from_ip, 127, 0, 0, 1);
                v.nonce = 0x5151515151515151ULL; v.user_agent = "/nf:0/"; v.start_height = PN;
                uint8_t vb[256]; size_t vn = kw_msg_version_build(&v, vb, sizeof vb);
                if (!vn || !frame_send(c->fd, "version", vb, vn) || !frame_send(c->fd, "verack", NULL, 0)) goto done;
            } else if (!strcmp(cmd, "getheaders")) {
                if (!reply(c, pl, pn)) goto done;
            } else if (!strcmp(cmd, "ping")) frame_send(c->fd, "pong", pl, pn);
            memmove(buf, buf + used, have - (size_t)used); have -= (size_t)used;
        }
        if (have == sizeof buf) have = 0;
    }
done:
    close(c->fd); free(c);
    __atomic_sub_fetch(&live_conns, 1, __ATOMIC_SEQ_CST);
    return NULL;
}

static void *acceptor(void *a)
{
    (void)a;
    for (;;) {
        int fd = accept(ls, NULL, NULL);
        if (fd < 0) continue;
        struct conn *c = (struct conn *)calloc(1, sizeof *c); c->fd = fd;
        pthread_mutex_lock(&tm);
        int k = conn_no++;
        if (k < ntapes) { memcpy(c->tape, tapes[k], TAPE); c->tn = tlen[k]; }
        pthread_mutex_unlock(&tm);
        __atomic_add_fetch(&live_conns, 1, __ATOMIC_SEQ_CST);
        pthread_t t;
        if (pthread_create(&t, NULL, serve, c) == 0) pthread_detach(t);
        else { close(fd); free(c); __atomic_sub_fetch(&live_conns, 1, __ATOMIC_SEQ_CST); }
    }
    return NULL;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    signal(SIGPIPE, SIG_IGN);
    memset(anch, 0x11, 32);
    uint8_t raw[80];
    const uint8_t *pv = anch, *fv = anch;
    for (int i = 0; i < PN; i++) {
        memset(raw, 0, 80); raw[0] = (uint8_t)(i + 1); raw[68] = (uint8_t)i; memcpy(raw + 4, pv, 32);
        kw_block_header_parse(raw, 80, &ch[i]); pv = ch[i].hash;
        raw[69] = 0xee; memcpy(raw + 4, fv, 32);
        kw_block_header_parse(raw, 80, &forged[i]); fv = forged[i].hash;
    }
    dummy.chain = ch; dummy.n = PN;
    for (int i = 0; i <= PN; i++) {
        const uint8_t *hh = i ? ch[i - 1].hash : anch;
        for (int b = 0; b < 32; b++) snprintf(hexes[i] + b * 2, 3, "%02x", hh[31 - b]);
    }
    pcp = KW_DOGE_REGTEST; pcp.genesis = hexes[0];
    ls = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET; sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(ls, (struct sockaddr *)&sa, sizeof sa) || listen(ls, 64)) abort();
    socklen_t sl = sizeof sa; getsockname(ls, (struct sockaddr *)&sa, &sl); port = ntohs(sa.sin_port);
    pthread_t t; pthread_create(&t, NULL, acceptor, NULL); pthread_detach(t);
    const char *d = getenv("FZ_TMP");
    snprintf(cpath, sizeof cpath, "%s/pf-%d.kwh", d ? d : "/tmp", (int)getpid());
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2) return 0;
    nf_in in = { data, size };
    uint8_t cfg = in8(&in);
    int workers = 1 + (cfg & 3), nhosts = 1 + ((cfg >> 2) & 3), layout = (cfg >> 4) & 3;
    /* wait out the previous input's connections so tape numbering starts clean */
    for (int i = 0; i < 2000 && __atomic_load_n(&live_conns, __ATOMIC_SEQ_CST); i++) usleep(1000);
    pthread_mutex_lock(&tm);
    ntapes = in8(&in) % (MAXT + 1); conn_no = 0;
    for (int k = 0; k < ntapes; k++) {
        tlen[k] = in8(&in) % (TAPE + 1);
        size_t g; const uint8_t *b = intake(&in, (size_t)tlen[k], &g);
        memset(tapes[k], 0, TAPE); memcpy(tapes[k], b, g); tlen[k] = (int)g;
    }
    pthread_mutex_unlock(&tm);

    int nc = 0;
    switch (layout) {
    case 0: for (int h = 0; h <= PN; h += 10) cps[nc++].height = (uint32_t)h; break;
    case 1: for (int h = 0; h < PN; h += 7) cps[nc++].height = (uint32_t)h; cps[nc++].height = PN; break;
    case 2: for (int h = 0; h <= 8; h++) cps[nc++].height = (uint32_t)h; cps[nc++].height = PN; break;
    default: cps[nc++].height = 0; cps[nc++].height = PN; break;
    }
    for (int i = 0; i < nc; i++) cps[i].hash = hexes[cps[i].height];
    pcp.checkpoints = cps; pcp.ncheckpoints = (size_t)nc;

    char addr[4][32]; const char *hosts[4];
    for (int i = 0; i < nhosts; i++) { snprintf(addr[i], sizeof addr[i], "127.0.0.1:%u", (unsigned)port); hosts[i] = addr[i]; }
    char part[4200]; snprintf(part, sizeof part, "%s.part", cpath);
    remove(cpath); remove(part);
    const char *best = NULL;
    long r = kw_psync_headers(&pcp, hosts, (size_t)nhosts, 0, 0, workers, cpath, &best);
    if (getenv("NF_DEBUG")) fprintf(stderr, "workers %d hosts %d layout %d tapes %d conns %d -> %ld\n", workers, nhosts, layout, ntapes, conn_no, r);

    FILE *pf = fopen(part, "rb"); int part_left = pf != NULL; if (pf) fclose(pf);
    FILE *cf = fopen(cpath, "rb"); int cache = cf != NULL; if (cf) fclose(cf);
    if (r == 0) NF_FAIL("F3 returned 0 with no cache present");
    if (r == PN) {
        if (part_left) NF_FAIL("F1 .part left after success");
        kw_headerstore s; kw_headerstore_init(&s);
        if (!kw_headerstore_load(&s, cpath)) NF_FAIL("F1 filled cache does not load");
        if (s.count != PN) NF_FAIL("F1 cache holds %zu", s.count);
        for (int i = 0; i < PN; i++) if (memcmp(s.h[i].hash, ch[i].hash, 32) || memcmp(s.h[i].raw, ch[i].raw, 80)) NF_FAIL("F1 height %d is not the honest header", i + 1);
        kw_headerstore_free(&s);
    } else if (r == -1) {
        if (part_left || cache) NF_FAIL("F2 failure left part %d cache %d", part_left, cache);
    } else NF_FAIL("F? returned %ld", r);
    remove(cpath); remove(part);
    return 0;
}
