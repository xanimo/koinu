/* netfuzz target 7: kw_spv_sync_blocks (scan --spv / sweep without filters) over a
   scripted peer serving the blocks of a small real chain, honest, mutated, out of
   order, or with another block's header spliced on.

   input: [cfg][chain...][peer script...]   cfg bit0: also watch script B

   V1 on success the return equals the number of headers
   V2 on success the utxo set equals an independent replay of the honest chain:
      per tx, each input removes one matching (txid,vout), then each output paying
      a watched script is added at that block's height (multiset compare; heights
      compared only when no outpoint key ever repeats)
   V3 the set's total equals the sum of its values */
#include "script.h"
#include "blocks.h"
#include "spv.h"
#include "utxo.h"
#include "tx.h"
#include <signal.h>

static const kw_chainparams *CP = &KW_DOGE_REGTEST;
struct vctx { nb_chain *c; int bcur; };

static int st_op(void *v, nf_in *in, nf_peer *pp, int op)
{
    struct vctx *x = (struct vctx *)v;
    nb_chain *c = x->c;
    uint8_t sel = in8(in), m = in8(in);
    if (m & 0x80) m = 0;
    int b = (sel & 0x80) ? x->bcur++ % c->nb : sel % c->nb;
    switch (op & 3) {
    case 1: nb_serve_block(&pp->script, CP->magic, c, b, m, in); break;
    case 2: {                                   /* block b's body under block b2's header */
        int b2 = in8(in) % c->nb;
        nf_buf y = {0}; nb_put(&y, c->body[b].b, c->body[b].n); memcpy(y.b, c->hdr[b2].raw, 80);
        nf_frame(&pp->script, CP->magic, "block", y.b, y.n, 1, 0, 0); nb_free(&y);
        break; }
    case 3: {                                   /* block b with a tx duplicated at the end (CVE-2012-2459 shape) */
        nf_buf y = {0};
        if (c->ntx[b] >= 1 && c->ntx[b] < 250) {
            /* re-serialise: header, ntx+1, txs, last tx again */
            size_t off = 80; uint8_t n0 = c->body[b].b[off];
            nb_put(&y, c->body[b].b, 80); nb_u8(&y, (uint8_t)(n0 + 1));
            nb_put(&y, c->body[b].b + 81, c->body[b].n - 81);
            /* last tx length: rescan */
            size_t o = 81, last = 81;
            for (int t = 0; t < c->ntx[b]; t++) { last = o; size_t k = kw_tx_scan(c->body[b].b + o, c->body[b].n - o, NULL, NULL, NULL, NULL); if (!k) break; o += k; }
            nb_put(&y, c->body[b].b + last, c->body[b].n - last);
            nf_frame(&pp->script, CP->magic, "block", y.b, y.n, 1, 0, 0);
        }
        nb_free(&y);
        break; }
    }
    return 1;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    nf_genesis(CP, nf_gen);
    signal(SIGPIPE, SIG_IGN);
    return 0;
}

typedef struct { uint8_t txid[32]; uint32_t vout; uint64_t value; uint32_t h; size_t sl; uint8_t spk[40]; int live; } ou;

static int ou_cmp(const void *a, const void *b)
{
    const ou *x = (const ou *)a, *y = (const ou *)b;
    int r = memcmp(x->txid, y->txid, 32); if (r) return r;
    if (x->vout != y->vout) return x->vout < y->vout ? -1 : 1;
    if (x->value != y->value) return x->value < y->value ? -1 : 1;
    if (x->h != y->h) return x->h < y->h ? -1 : 1;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 3) return 0;
    nf_in in = { data, size };
    uint8_t cfg = in8(&in);
    nb_chain *c = (nb_chain *)calloc(1, sizeof *c);
    nb_build(c, &in, nf_gen, CP->genesis_time);

    kw_headerstore s; kw_headerstore_init(&s);
    for (int b = 0; b < c->nb; b++) kw_headerstore_append(&s, &c->hdr[b]);
    kw_watchset ws; kw_watchset_init(&ws);
    kw_watchset_add(&ws, NB_SPK_A, 25);
    if (cfg & 1) kw_watchset_add(&ws, NB_SPK_B, 25);
    kw_utxoset us; kw_utxoset_init(&us);

    nf_peer pp; kw_peer lp; memset(&pp, 0, sizeof pp);
    nf_peer_open(&pp, &lp, CP);
    struct vctx x = { c, 0 };
    nf_script(&in, &pp, CP->magic, 40, st_op, &x);
    nf_peer_start(&pp);
    long ret = kw_spv_sync_blocks(&lp, &s, &us, &ws, 1);
    kw_peer_close(&lp);
    nf_peer_finish(&pp);
    if (getenv("NF_DEBUG")) fprintf(stderr, "nb=%d ret=%ld utxos=%zu total=%llu\n", c->nb, ret, us.count, (unsigned long long)us.total);

    if (ret >= 0) {
        if (ret != (long)s.count) NF_FAIL("V1 returned %ld for %zu headers", ret, s.count);
        ou *o = (ou *)calloc(NB_MAXB * NB_MAXTX * NB_MAXOUT + 1, sizeof *o); int no = 0, rep = 0;
        for (int b = 0; b < c->nb; b++)
            for (int t = 0; t < c->ntx[b]; t++) {
                for (int i = 0; i < c->nin[b][t]; i++)
                    for (int k = 0; k < no; k++)
                        if (o[k].live && o[k].vout == c->pvout[b][t][i] && !memcmp(o[k].txid, c->prev[b][t][i], 32)) { o[k].live = 0; break; }
                for (int q = 0; q < c->nout[b][t]; q++) {
                    size_t sl = c->spklen[b][t][q];
                    int w = sl == 25 && (!memcmp(c->spk[b][t][q], NB_SPK_A, 25) || ((cfg & 1) && !memcmp(c->spk[b][t][q], NB_SPK_B, 25)));
                    if (!w) continue;
                    for (int k = 0; k < no; k++) if (o[k].vout == (uint32_t)q && !memcmp(o[k].txid, c->txid[b][t], 32)) rep = 1;
                    ou *e = &o[no++]; memcpy(e->txid, c->txid[b][t], 32); e->vout = (uint32_t)q; e->value = c->val[b][t][q];
                    e->h = (uint32_t)b + 1; e->sl = sl; memcpy(e->spk, c->spk[b][t][q], sl); e->live = 1;
                }
            }
        int nl = 0; for (int k = 0; k < no; k++) if (o[k].live) o[nl++] = o[k];
        uint64_t tot = 0;
        ou *g = (ou *)calloc(us.count + 1, sizeof *g);
        for (size_t i = 0; i < us.count; i++) {
            memcpy(g[i].txid, us.u[i].txid, 32); g[i].vout = us.u[i].vout; g[i].value = us.u[i].value; g[i].h = us.u[i].height;
            tot += us.u[i].value;
        }
        if (tot != us.total) NF_FAIL("V3 total %llu, sum %llu", (unsigned long long)us.total, (unsigned long long)tot);
        if (rep) { for (int k = 0; k < nl; k++) o[k].h = 0; for (size_t i = 0; i < us.count; i++) g[i].h = 0; }
        qsort(o, (size_t)nl, sizeof *o, ou_cmp); qsort(g, us.count, sizeof *g, ou_cmp);
        if ((size_t)nl != us.count) NF_FAIL("V2 %zu utxos, replay has %d", us.count, nl);
        for (int k = 0; k < nl; k++) if (ou_cmp(&o[k], &g[k])) NF_FAIL("V2 utxo %d differs from the replay", k);
        free(o); free(g);
    }
    kw_utxoset_free(&us); kw_watchset_free(&ws);
    kw_headerstore_free(&s);
    nb_free_chain(c); free(c);
    return 0;
}
