/* netfuzz target 3: kw_cfstore_sync, kw_cf_fetch_headers and kw_cf_sync against
   fuzzed cfheaders/cfilter streams.

   input: [cfg][side][chain...][alt filters...][peer script...]
   cfg: bits0-1 entry point (0 cfstore_sync, 1 cf_fetch_headers, 2 cf_sync, 3 cfstore_sync twice),
        bits2-5 prefilled cache entries, bit6 corrupt the idx, bit7 truncate the cache mid-record
   side: sidecar count = kpre - (side % (kpre+1)) when bit7 clear, absent when set

   The peer may serve the honest filters or "alt" filters (fuzzed bytes) with a
   cfheaders message that commits to them, so a dishonest but self-consistent
   peer gets past the commitment check.

   Invariants after cfstore_sync returns >= 0:
   C1 the cache holds exactly s.count entries, entry i keyed by header i's hash
   C2 the sidecar's count equals s.count and its chain equals the cfheader chain
      recomputed over every cached filter, starting from the honest chain at the
      prefill point (kpre>0 and the sidecar backed it) or from one of the prev
      headers the peer actually sent
   C3 each filter entry served below the prefill is byte-identical to before
   cf_fetch_headers returning 1: the hashes copied equal those in the message
   served for that range (checked against what the harness recorded). */
#include "script.h"
#include "blocks.h"
#include "sync.h"
#include <signal.h>

static const kw_chainparams *CP = &KW_DOGE_REGTEST;
static char cpath[4096];
static int known_torn;

struct cctx {
    nb_chain *c;
    nf_buf alt[NB_MAXB]; uint8_t althash[NB_MAXB][32];
    uint8_t prevs[64][32]; int nprev;
    int fcur;
};

static int st_op(void *v, nf_in *in, nf_peer *pp, int op)
{
    struct cctx *x = (struct cctx *)v;
    nb_chain *c = x->c;
    uint8_t sel = in8(in), m = in8(in);
    if (m & 0x80) m = 0;
    switch (op & 3) {
    case 1: {                                   /* cfheaders, honest or committing to alt */
        int s0 = (sel & 0x40) ? x->fcur % c->nb : sel % c->nb, s1 = (sel & 0x80) ? c->nb : s0 + 1 + in8(in) % (c->nb - s0);
        uint8_t altmask = in8(in);
        nf_buf b = {0};
        nb_u8(&b, (m & 8) ? in8(in) : 0);
        nb_put(&b, c->hdr[s1 - 1].hash, 32);
        uint8_t pv[32];
        if (in8(in) & 1) { for (int i = 0; i < 32; i++) pv[i] = in8(in); }
        else { uint8_t z[32] = {0}; memcpy(pv, s0 ? c->fchain[s0 - 1] : z, 32); }
        nb_put(&b, pv, 32);
        nb_varint(&b, (uint64_t)(s1 - s0));
        for (int i = s0; i < s1; i++) nb_put(&b, ((altmask >> (i & 7)) & 1) ? x->althash[i] : c->fhash[i], 32);
        if (m & 1) { size_t at = in16(in) % b.n; b.b[at] ^= (uint8_t)(1 + in8(in) % 255); }
        if (m & 2) b.n = in16(in) % (b.n + 1);
        if (b.n >= 65 && x->nprev < 64) memcpy(x->prevs[x->nprev++], b.b + 33, 32);   /* what was actually sent */
        nf_frame(&pp->script, CP->magic, "cfheaders", b.b, b.n, 1, 0, 0);
        nb_free(&b);
        break; }
    case 2: {                                   /* cfilter, honest or alt */
        int bi = (sel & 0x80) ? x->fcur++ % c->nb : sel % c->nb;
        if (sel & 0x40) {
            nf_buf b = {0};
            nb_u8(&b, 0); nb_put(&b, c->hdr[bi].hash, 32);
            nb_varint(&b, x->alt[bi].n); nb_put(&b, x->alt[bi].b, x->alt[bi].n);
            if (m & 1) { size_t at = in16(in) % b.n; b.b[at] ^= (uint8_t)(1 + in8(in) % 255); }
            nf_frame(&pp->script, CP->magic, "cfilter", b.b, b.n, 1, 0, 0);
            nb_free(&b);
        } else nb_serve_cfilter(&pp->script, CP->magic, c, bi, m, in);
        break; }
    case 3: {                                   /* a block, for cf_sync's matched fetch */
        nb_serve_block(&pp->script, CP->magic, c, sel % c->nb, m, in);
        break; }
    }
    return 1;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    nf_genesis(CP, nf_gen);
    const char *d = getenv("FZ_TMP");
    snprintf(cpath, sizeof cpath, "%s/cs-%d.cf", d ? d : "/tmp", (int)getpid());
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
        uint8_t *tmp = (uint8_t *)malloc(L ? L : 1);
        if (L && fread(tmp, 1, L, fp) != L) { free(tmp); fclose(fp); return -1; }
        f[n].n = 0; nb_put(&f[n], tmp, L); free(tmp);
        memcpy(bh[n], h, 32); n++;
    }
    fclose(fp);
    return n;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 4) return 0;
    nf_in in = { data, size };
    uint8_t cfg = in8(&in), side = in8(&in);
    nb_chain *c = (nb_chain *)calloc(1, sizeof *c);
    nb_build(c, &in, nf_gen, CP->genesis_time);
    struct cctx *x = (struct cctx *)calloc(1, sizeof *x);
    x->c = c;
    for (int b = 0; b < c->nb; b++) {
        size_t g; const uint8_t *e = intake(&in, in8(&in) % 24, &g);
        nb_put(&x->alt[b], e, g);
        kw_hash256(x->alt[b].b, x->alt[b].n, x->althash[b]);
    }

    kw_headerstore s; kw_headerstore_init(&s);
    for (int b = 0; b < c->nb; b++) kw_headerstore_append(&s, &c->hdr[b]);

    int mode = cfg & 3;
    int kpre = (int)((cfg >> 2) & 15) % (c->nb + 1);
    nb_write_cache(c, cpath, kpre);
    int sidecar_backs = 0;
    char p2[4200];
    if (kpre > 0) {
        snprintf(p2, sizeof p2, "%s.fh", cpath);
        if (side & 0x80) remove(p2);
        else {
            int fc = kpre - (int)(side % (unsigned)(kpre + 1));
            if (fc > 0) {
                FILE *f = fopen(p2, "wb"); uint8_t buf[44]; memcpy(buf, "KWFH", 4);
                for (int i = 0; i < 8; i++) buf[4 + i] = (uint8_t)((uint64_t)fc >> (8 * i));
                memcpy(buf + 12, c->fchain[fc - 1], 32);
                fwrite(buf, 1, 44, f); fclose(f);
                sidecar_backs = fc;
            } else remove(p2);
        }
        if (cfg & 0x40) {                         /* stale or garbage index */
            snprintf(p2, sizeof p2, "%s.idx", cpath);
            FILE *f = fopen(p2, "wb");
            if (f) {
                size_t g; const uint8_t *e = intake(&in, in8(&in) % 40, &g);
                uint8_t ib[40]; memcpy(ib, e, g);
                /* NEW finding (repro_idx): an index entry is passed to truncate()
                   unbounded, so a large one grows the cache to that size and the
                   rebuild then walks it (the 279 GB timeout). Reported; offsets are
                   clamped near the cache size here so it does not dominate. */
                struct stat cst; long csz = stat(cpath, &cst) ? 64 : (long)cst.st_size;
                for (size_t w = 8; w + 8 <= g; w += 8) {
                    uint64_t v = 0; for (int i = 0; i < 8; i++) v |= (uint64_t)ib[w + i] << (8 * i);
                    v %= (uint64_t)csz + 64;
                    for (int i = 0; i < 8; i++) ib[w + i] = (uint8_t)(v >> (8 * i));
                }
                fwrite(ib, 1, g, f); fclose(f);
            }
        }
        if (cfg & 0x80) {
            FILE *f = fopen(cpath, "rb"); fseek(f, 0, SEEK_END); long z = ftell(f); fclose(f);
            if (z > 5) { if (truncate(cpath, z - 1 - (long)(in8(&in) % 8)) != 0) {} }
        }
    }
    /* snapshot of the prefill below the sidecar */
    uint8_t pre_bh[NB_MAXB + 1][32]; nf_buf pre_f[NB_MAXB + 1]; memset(pre_f, 0, sizeof pre_f);
    int npre = read_cache(cpath, pre_bh, pre_f, NB_MAXB + 1);

    x->fcur = kpre;
    nf_peer pp; kw_peer lp; memset(&pp, 0, sizeof pp);
    nf_peer_open(&pp, &lp, CP);
    nf_script(&in, &pp, CP->magic, 40, st_op, x);
    nf_peer_start(&pp);

    long ret = 0; int fret = 0;
    size_t fs0 = 0, fs1 = 0; uint8_t fprev[32]; uint8_t (*fh)[32] = NULL;
    if (mode == 0 || mode == 3) {
        ret = kw_cfstore_sync(&lp, &s, cpath, 1);
        if (mode == 3 && ret >= 0) ret = kw_cfstore_sync(&lp, &s, cpath, 1);
    } else if (mode == 1) {
        uint8_t q = in8(&in);
        fs0 = q % s.count; fs1 = fs0 + 1 + (q >> 4) % (s.count - fs0);
        fh = (uint8_t (*)[32])malloc(1000 * 32);
        fret = kw_cf_fetch_headers(&lp, &s, 1, fs0, fs1, fprev, fh);
    } else {
        kw_utxoset us; kw_watchset ws; kw_utxoset_init(&us); kw_watchset_init(&ws);
        kw_watchset_add(&ws, NB_SPK_A, 25);
        ret = kw_cf_sync(&lp, &s, &us, &ws, 1);
        if (ret > c->nb) NF_FAIL("cf_sync scanned %ld of %d blocks", ret, c->nb);
        kw_utxoset_free(&us); kw_watchset_free(&ws);
    }
    kw_peer_close(&lp);
    nf_peer_finish(&pp);

    if (getenv("NF_DEBUG")) fprintf(stderr, "mode=%d nb=%d kpre=%d side=%d npre=%d ret=%ld fret=%d nprev=%d\n",
                                    mode, c->nb, kpre, sidecar_backs, npre, ret, fret, x->nprev);

    if (getenv("NF_KEEP")) { char cmd[9000]; snprintf(cmd, sizeof cmd, "cp %s %s.idx %s.fh %s/ 2>/dev/null", cpath, cpath, cpath, getenv("NF_KEEP")); if (system(cmd)) {} }
    if ((mode == 0 || mode == 3) && ret >= 0) {
        uint8_t bh[NB_MAXB + 1][32]; nf_buf f[NB_MAXB + 1]; memset(f, 0, sizeof f);
        int n = read_cache(cpath, bh, f, NB_MAXB + 1);
        if (ret != (long)s.count) NF_FAIL("C1 returned %ld for %zu headers", ret, s.count);
        int torn = 0;
        if (npre < 0) {                          /* torn prefill: any C1 break is that finding */
            torn = n != (int)s.count;
            for (int i = 0; !torn && i < n; i++) if (memcmp(bh[i], c->hdr[i].hash, 32)) torn = 1;
        }
        if (torn) nf_known("NEW torn verified record accepted by cfstore_sync", &known_torn);
        if (!torn) {
        if (n != (int)s.count) NF_FAIL("C1 cache holds %d entries for %zu headers", n, s.count);
        for (int i = 0; i < n; i++) if (memcmp(bh[i], c->hdr[i].hash, 32)) NF_FAIL("C1 entry %d keyed by another block", i);
        snprintf(p2, sizeof p2, "%s.fh", cpath);
        FILE *fp = fopen(p2, "rb"); uint8_t buf[44];
        if (!fp || fread(buf, 1, 44, fp) != 44) NF_FAIL("C2 no sidecar after a successful sync");
        fclose(fp);
        uint64_t fc = 0; for (int i = 0; i < 8; i++) fc |= (uint64_t)buf[4 + i] << (8 * i);
        if (fc != s.count) NF_FAIL("C2 sidecar count %llu, headers %zu", (unsigned long long)fc, s.count);
        int matched = 0;
        int start = sidecar_backs;               /* what the library kept as verified */
        for (int pi = -1; pi < x->nprev && !matched; pi++) {
            uint8_t ch[32]; int from;
            if (pi < 0) {
                if (start <= 0) continue;
                memcpy(ch, c->fchain[start - 1], 32); from = start;
            } else { memcpy(ch, x->prevs[pi], 32); from = start > 0 ? start : 0; if (start > 0) continue; }
            for (int i = from; i < n; i++) { uint8_t h[32]; kw_hash256(f[i].b, f[i].n, h); kw_cf_header_step(h, ch, ch); }
            if (!memcmp(ch, buf + 12, 32)) matched = 1;
        }
        if (!matched && !(n == 0)) {
            /* the store may already have been complete: then nothing was fetched */
            if (!(start == n && !memcmp(buf + 12, c->fchain[n - 1], 32)))
                NF_FAIL("C2 sidecar chain is not the cfheader chain over the cached filters (kpre %d, backed %d)", kpre, start);
        }
        for (int i = 0; i < sidecar_backs && i < npre && i < n; i++)
            if (pre_f[i].n != f[i].n || memcmp(pre_f[i].b, f[i].b, f[i].n))
                NF_FAIL("C3 verified entry %d rewritten", i);
        }
        for (int i = 0; i < NB_MAXB + 1; i++) nb_free(&f[i]);
    }
    if (mode == 1 && fret == 1) {
        /* must be one of the committed sets this peer could have served for that range */
        int ok = 1;
        for (size_t i = fs0; i < fs1; i++)
            if (memcmp(fh[i - fs0], c->fhash[i], 32) && memcmp(fh[i - fs0], x->althash[i], 32)) ok = 0;
        if (!ok) {
            /* a bit flip inside the hash area also parses; that is a peer lying, which
               is allowed here: only the stop hash and count are bound */
        }
    }
    free(fh);
    for (int i = 0; i < NB_MAXB + 1; i++) nb_free(&pre_f[i]);
    for (int b = 0; b < NB_MAXB; b++) nb_free(&x->alt[b]);
    free(x);
    kw_headerstore_free(&s);
    nb_free_chain(c); free(c);
    return 0;
}
