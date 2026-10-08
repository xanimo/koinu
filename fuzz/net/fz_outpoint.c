/* netfuzz target 2: kw_query_outpoint_range over a scripted peer, on the
   no-filter path and on the filter path with a pre-built cache.

   input: [cfg][since][chain...][peer script...]
   cfg: bit0 filter path, bits1-2 watched script (A, B, target's own, fuzzed),
        bits3-6 prefilled cache entries (mod nb+1)

   Invariants on a 1 return (heights are 1-based, base 1):
   O1 created implies the output at the outpoint pays the watched script
      (finding 1: reported once, then disabled)
   O2 the reported height lies in [since, tip] and tipheight is the store's tip
   O3 unspent: the block at the reported height creates the outpoint with
      exactly that value. spent: the block at that height spends it
   O4 no-filter path: the answer equals the chain's (every block was fetched)
   O5 filter path: the cache afterwards holds one entry per header, each keyed by
      that header's hash, and the sidecar chain recomputes from the cached
      filters (from the honest prefix when one was prefilled) */
#include "script.h"
#include "blocks.h"
#include "sync.h"
#include "spv.h"
#include <signal.h>

static const kw_chainparams *CP = &KW_DOGE_REGTEST;
static int known1;
static char cpath[4096];

struct octx { nb_chain *c; int bcur, fcur, kpre; };

static int st_op(void *v, nf_in *in, nf_peer *pp, int op)
{
    struct octx *x = (struct octx *)v;
    nb_chain *c = x->c;
    uint8_t sel = in8(in), m = in8(in);
    if (m & 0x80) m = 0;                         /* mostly honest */
    switch (op & 3) {
    case 1: {
        int b = (sel & 0x80) ? x->bcur++ % c->nb : sel % c->nb;
        nb_serve_block(&pp->script, CP->magic, c, b, m, in);
        break; }
    case 2: {
        int s0 = (sel & 0x80) ? x->kpre : sel % c->nb;
        int s1 = (sel & 0x40) ? in8(in) % (c->nb + 1) : c->nb;
        nb_serve_cfheaders(&pp->script, CP->magic, c, s0, s1, m, in);
        break; }
    case 3: {
        int b = (sel & 0x80) ? x->fcur++ % c->nb : sel % c->nb;
        nb_serve_cfilter(&pp->script, CP->magic, c, b, m, in);
        break; }
    }
    return 1;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    nf_genesis(CP, nf_gen);
    const char *d = getenv("FZ_TMP");
    snprintf(cpath, sizeof cpath, "%s/op-%d.cf", d ? d : "/tmp", (int)getpid());
    signal(SIGPIPE, SIG_IGN);
    return 0;
}

static int read_cache(const char *path, uint8_t (*bh)[32], nf_buf *f, int max)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return 0;
    uint8_t m[4];
    if (fread(m, 1, 4, fp) != 4) { fclose(fp); return -1; }
    int n = 0;
    for (;;) {
        uint8_t h[32];
        size_t r = fread(h, 1, 32, fp);
        if (r == 0) break;
        if (r != 32 || n >= max) { fclose(fp); return -1; }
        int c0 = fgetc(fp); uint64_t L = (uint64_t)c0;
        if (c0 >= 0xfd) { int k = c0 == 0xfd ? 2 : c0 == 0xfe ? 4 : 8; L = 0; for (int i = 0; i < k; i++) L |= (uint64_t)fgetc(fp) << (8 * i); }
        if (L > 1 << 20) { fclose(fp); return -1; }
        f[n].n = 0; uint8_t *tmp = (uint8_t *)malloc(L ? L : 1);
        if (L && fread(tmp, 1, L, fp) != L) { free(tmp); fclose(fp); return -1; }
        nb_put(&f[n], tmp, L); free(tmp);
        memcpy(bh[n], h, 32); n++;
    }
    fclose(fp);
    return n;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 4) return 0;
    nf_in in = { data, size };
    uint8_t cfg = in8(&in), sincesel = in8(&in);
    nb_chain *c = (nb_chain *)calloc(1, sizeof *c);
    nb_build(c, &in, nf_gen, CP->genesis_time);
    int filt = cfg & 1;
    if (getenv("NF_DEBUG")) fprintf(stderr, "after chain: consumed %zu\n", size - in.n);
    uint32_t since = sincesel % (uint32_t)(c->nb + 2);

    uint8_t wspk[40]; size_t wlen;
    switch ((cfg >> 1) & 3) {
    case 0: memcpy(wspk, NB_SPK_A, 25); wlen = 25; break;
    case 1: memcpy(wspk, NB_SPK_B, 25); wlen = 25; break;
    case 2: memcpy(wspk, NB_SPK_A, 25); wlen = 25;
        for (int b = 0; b < c->nb; b++) for (int t = 0; t < c->ntx[b]; t++)
            if (!memcmp(c->txid[b][t], c->ttxid, 32) && (int)c->tvout < c->nout[b][t] && c->spklen[b][t][c->tvout]) {
                wlen = c->spklen[b][t][c->tvout]; memcpy(wspk, c->spk[b][t][c->tvout], wlen); }
        break;
    default: wlen = 1 + in8(&in) % 39; for (size_t i = 0; i < wlen; i++) wspk[i] = in8(&in);
    }

    if (getenv("NF_DEBUG")) for (int b = 0; b < c->nb; b++) {
        kw_outpoint_status st = {0,0,0,0};
        fprintf(stderr, "blk %d ntx %d merkle_ok %d find %d\n", b, c->ntx[b], kw_block_merkle_ok(c->body[b].b, c->body[b].n),
                kw_block_find_outpoint(c->body[b].b, c->body[b].n, c->ttxid, c->tvout, wspk, wlen, &st));
    }
    kw_headerstore s; kw_headerstore_init(&s);
    for (int b = 0; b < c->nb; b++) kw_headerstore_append(&s, &c->hdr[b]);

    int kpre = filt ? (int)((cfg >> 3) % (unsigned)(c->nb + 1)) : 0;
    if (filt) nb_write_cache(c, cpath, kpre);

    nf_peer pp; kw_peer lp; memset(&pp, 0, sizeof pp);
    nf_peer_open(&pp, &lp, CP);
    struct octx x = { c, 0, kpre, kpre };
    nf_script(&in, &pp, CP->magic, 40, st_op, &x);
    nf_peer_start(&pp);

    kw_outpoint_result r; memset(&r, 0, sizeof r);
    int ret = kw_query_outpoint_range(&lp, &s, filt ? cpath : NULL, 1, wspk, wlen,
                                      c->ttxid, c->tvout, since, &r);
    kw_peer_close(&lp);
    nf_peer_finish(&pp);

    if (getenv("NF_DEBUG")) fprintf(stderr, "nb=%d filt=%d kpre=%d since=%u ret=%d status=%d h=%ld v=%llu tip=%ld\n",
                                    c->nb, filt, kpre, since, ret, r.status, r.height, (unsigned long long)r.value, r.tipheight);
    if (ret == 1) {
        long th = 0; uint64_t tv = 0;
        int truth = nb_truth(c, 1, since, &th, &tv, NULL, 0, 0);
        if (r.tipheight != (long)s.count) NF_FAIL("O2 tipheight %ld, store %zu", r.tipheight, s.count);
        if (r.status != 2 && (r.height < (long)since || r.height < 1 || r.height > (long)s.count))
            NF_FAIL("O2 height %ld outside [%u, %zu]", r.height, since, s.count);
        if (r.status == 0) {
            int b = (int)r.height - 1, ok = 0, pays = 0;
            for (int t = 0; t < c->ntx[b]; t++)
                if (!memcmp(c->txid[b][t], c->ttxid, 32) && (int)c->tvout < c->nout[b][t] &&
                    c->val[b][t][c->tvout] == r.value) {
                    ok = 1;
                    pays |= c->spklen[b][t][c->tvout] == wlen && !memcmp(c->spk[b][t][c->tvout], wspk, wlen);
                }
            if (!ok) NF_FAIL("O3 unspent at %ld value %llu not in that block", r.height, (unsigned long long)r.value);
            if (!pays) nf_known("finding 1: created output does not pay the watched script", &known1);
        } else if (r.status == 1) {
            int b = (int)r.height - 1, ok = 0;
            for (int t = 0; t < c->ntx[b]; t++)
                for (int i = 0; i < c->nin[b][t]; i++)
                    if (c->pvout[b][t][i] == c->tvout && !memcmp(c->prev[b][t][i], c->ttxid, 32)) ok = 1;
            if (!ok) NF_FAIL("O3 spent at %ld but that block does not spend it", r.height);
        }
        if (!filt && (r.status != truth || (truth != 2 && (r.height != th || (truth == 0 && r.value != tv)))))
            NF_FAIL("O4 no-filter answer %d/%ld/%llu, chain says %d/%ld/%llu", r.status, r.height,
                    (unsigned long long)r.value, truth, th, (unsigned long long)tv);
    }
    if (filt && ret == 1) {
        uint8_t bh[NB_MAXB + 1][32]; nf_buf f[NB_MAXB + 1]; memset(f, 0, sizeof f);
        int n = read_cache(cpath, bh, f, NB_MAXB + 1);
        if (n != c->nb) NF_FAIL("O5 cache holds %d entries for %d headers", n, c->nb);
        for (int i = 0; i < n; i++) if (memcmp(bh[i], c->hdr[i].hash, 32)) NF_FAIL("O5 entry %d keyed wrong", i);
        if (kpre > 0) {
            uint8_t ch[32]; memcpy(ch, c->fchain[kpre - 1], 32);
            for (int i = kpre; i < n; i++) { uint8_t fh[32]; kw_hash256(f[i].b, f[i].n, fh); kw_cf_header_step(fh, ch, ch); }
            char p2[4200]; snprintf(p2, sizeof p2, "%s.fh", cpath);
            FILE *fp = fopen(p2, "rb"); uint8_t buf[44] = {0};
            if (!fp || fread(buf, 1, 44, fp) != 44) NF_FAIL("O5 sidecar unreadable");
            fclose(fp);
            if (memcmp(buf + 12, ch, 32)) NF_FAIL("O5 sidecar chain does not recompute from the cached filters");
        }
        for (int i = 0; i < NB_MAXB + 1; i++) nb_free(&f[i]);
    }

    kw_headerstore_free(&s);
    nb_free_chain(c); free(c);
    return 0;
}
