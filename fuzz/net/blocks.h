/* netfuzz: a small fuzz-shaped chain of real blocks (bodies hash to their
   headers' merkle roots, headers link from regtest genesis) with honest filters
   and an honest filter-header chain, so harnesses can serve any of it. */
#ifndef NF_BLOCKS_H
#define NF_BLOCKS_H
#include "nf.h"
#include "cf.h"
#include "cfstore.h"

#define NB_MAXB 10
#define NB_MAXTX 4
#define NB_MAXOUT 3

static const uint8_t NB_SPK_A[25] = { 0x76,0xa9,0x14, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20, 0x88,0xac };
static const uint8_t NB_SPK_B[25] = { 0x76,0xa9,0x14, 9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9, 0x88,0xac };

static int nb_mine_headers;
typedef struct {
    int nb;
    nf_buf body[NB_MAXB];           /* full block message payload */
    kw_block_header hdr[NB_MAXB];
    int ntx[NB_MAXB];
    uint8_t txid[NB_MAXB][NB_MAXTX][32];
    /* outputs, for the oracle */
    int nout[NB_MAXB][NB_MAXTX];
    uint64_t val[NB_MAXB][NB_MAXTX][NB_MAXOUT];
    uint8_t spk[NB_MAXB][NB_MAXTX][NB_MAXOUT][40]; size_t spklen[NB_MAXB][NB_MAXTX][NB_MAXOUT];
    /* inputs */
    int nin[NB_MAXB][NB_MAXTX];
    uint8_t prev[NB_MAXB][NB_MAXTX][2][32]; uint32_t pvout[NB_MAXB][NB_MAXTX][2];
    /* filters */
    nf_buf filt[NB_MAXB];
    uint8_t fhash[NB_MAXB][32];
    uint8_t fchain[NB_MAXB][32];    /* filter header after block i; prev of 0 is zero */
    /* the target outpoint */
    uint8_t ttxid[32]; uint32_t tvout;
} nb_chain;

static void nb_free_chain(nb_chain *c)
{
    for (int i = 0; i < NB_MAXB; i++) { nb_free(&c->body[i]); nb_free(&c->filt[i]); }
}

/* Build from input. The target outpoint is chosen as some (block,tx,vout) of
   the chain, or a random one. Inputs may spend the target. */
static void nb_build(nb_chain *c, nf_in *in, const uint8_t genesis[32], uint32_t t0)
{
    memset(c, 0, sizeof *c);
    c->nb = 1 + in8(in) % NB_MAXB;
    uint8_t tsel = in8(in);
    int tb = tsel % c->nb, tt = (tsel >> 4) % NB_MAXTX;
    c->tvout = in8(in) % 4;
    memset(c->ttxid, 0x77, 32);                        /* replaced if (tb,tt) exists */
    const uint8_t *prevh = genesis;
    for (int b = 0; b < c->nb; b++) {
        int ntx = 1 + in8(in) % NB_MAXTX;
        c->ntx[b] = ntx;
        nf_buf txs = {0};
        uint8_t (*ids)[32] = c->txid[b];
        for (int t = 0; t < ntx; t++) {
            nf_buf tx = {0};
            nb_le32(&tx, 1);
            uint8_t f = in8(in);
            int nin = (b == 0 && t == 0) ? 1 : f % 3;
            c->nin[b][t] = nin;
            nb_varint(&tx, (uint64_t)nin);
            for (int i = 0; i < nin; i++) {
                uint8_t pv[32]; uint32_t vo;
                if ((f >> (2 + i)) & 1) { memcpy(pv, c->ttxid, 32); vo = c->tvout; }     /* spends the target */
                else { memset(pv, 0x33, 32); pv[0] = (uint8_t)b; pv[1] = (uint8_t)t; vo = (uint32_t)i; }
                memcpy(c->prev[b][t][i], pv, 32); c->pvout[b][t][i] = vo;
                nb_put(&tx, pv, 32); nb_le32(&tx, vo);
                nb_varint(&tx, 2); nb_u8(&tx, (uint8_t)b); nb_u8(&tx, (uint8_t)t);   /* scriptSig keeps txids distinct */
                nb_le32(&tx, 0xffffffffu);
            }
            int nout = 1 + (f >> 5) % NB_MAXOUT;
            c->nout[b][t] = nout;
            nb_varint(&tx, (uint64_t)nout);
            for (int o = 0; o < nout; o++) {
                uint8_t sf = in8(in);
                uint64_t v = (sf & 0x80) ? in64(in) : (uint64_t)(sf + 1) * 100000000ull;
                const uint8_t *sp; size_t sl; uint8_t fz[40];
                switch (sf & 3) {
                case 0: sp = NB_SPK_A; sl = 25; break;
                case 1: sp = NB_SPK_B; sl = 25; break;
                case 2: sl = in8(in) % 40; for (size_t k = 0; k < sl; k++) fz[k] = in8(in); sp = fz; break;
                default: { static const uint8_t ret[3] = { 0x6a, 1, 0 }; sp = ret; sl = 3; }
                }
                c->val[b][t][o] = v; memcpy(c->spk[b][t][o], sp, sl); c->spklen[b][t][o] = sl;
                nb_le64(&tx, v); nb_varint(&tx, sl); nb_put(&tx, sp, sl);
            }
            nb_le32(&tx, 0);
            kw_hash256(tx.b, tx.n, ids[t]);
            if (b == tb && t == tt) memcpy(c->ttxid, ids[t], 32);
            nb_put(&txs, tx.b, tx.n);
            nb_free(&tx);
        }
        uint8_t root[32]; nf_merkle(ids, (size_t)ntx, root);
        uint8_t raw[80];
        nf_hdr_fill(raw, 1, prevh, root, t0 + 60u * (uint32_t)(b + 1), NF_EASY, (uint32_t)b << 8);
        if (nb_mine_headers) nf_mine_cached(raw, 1);
        kw_block_header_parse(raw, 80, &c->hdr[b]);
        nb_put(&c->body[b], raw, 80);
        nb_varint(&c->body[b], (uint64_t)ntx);
        nb_put(&c->body[b], txs.b, txs.n);
        nb_free(&txs);
        prevh = c->hdr[b].hash;

        /* honest filter: every output script except empty and OP_RETURN */
        const uint8_t *items[NB_MAXTX * NB_MAXOUT]; size_t lens[NB_MAXTX * NB_MAXOUT]; size_t ni = 0;
        for (int t = 0; t < ntx; t++)
            for (int o = 0; o < c->nout[b][t]; o++) {
                if (!c->spklen[b][t][o] || c->spk[b][t][o][0] == 0x6a) continue;
                int dup = 0;
                for (size_t k = 0; k < ni; k++)
                    if (lens[k] == c->spklen[b][t][o] && !memcmp(items[k], c->spk[b][t][o], lens[k])) dup = 1;
                if (dup) continue;
                items[ni] = c->spk[b][t][o]; lens[ni] = c->spklen[b][t][o]; ni++;
            }
        nf_gcs_build(&c->filt[b], c->hdr[b].hash, items, lens, ni);
        kw_hash256(c->filt[b].b, c->filt[b].n, c->fhash[b]);
        uint8_t z[32] = {0};
        kw_cf_header_step(c->fhash[b], b ? c->fchain[b - 1] : z, c->fchain[b]);
    }
}

/* the oracle: what the chain says about the target over [since, tip], heights
   base+i. Returns 0 unspent / 1 spent / 2 none, as kw_query_outpoint_range. */
static int nb_truth(const nb_chain *c, uint32_t base, uint32_t since, long *height, uint64_t *value,
                    const uint8_t *spk, size_t spklen, int check_spk)
{
    long ch = -1, sh = -1; uint64_t v = 0;
    for (int b = 0; b < c->nb; b++) {
        if (base + (uint32_t)b < since) continue;
        for (int t = 0; t < c->ntx[b]; t++) {
            for (int i = 0; i < c->nin[b][t]; i++)
                if (c->pvout[b][t][i] == c->tvout && !memcmp(c->prev[b][t][i], c->ttxid, 32)) sh = base + b;
            if (!memcmp(c->txid[b][t], c->ttxid, 32) && (int)c->tvout < c->nout[b][t]) {
                if (check_spk && (c->spklen[b][t][c->tvout] != spklen || memcmp(c->spk[b][t][c->tvout], spk, spklen))) continue;
                ch = base + b; v = c->val[b][t][c->tvout];
            }
        }
    }
    if (sh >= 0) { *height = sh; return 1; }
    if (ch >= 0) { *height = ch; *value = v; return 0; }
    return 2;
}

/* write an honest cache of the first (n) filters with its sidecar */
static int nb_write_cache(const nb_chain *c, const char *path, int n)
{
    char p2[4200];
    remove(path);
    snprintf(p2, sizeof p2, "%s.idx", path); remove(p2);
    snprintf(p2, sizeof p2, "%s.fh", path); remove(p2);
    if (n <= 0) return 1;
    for (int i = 0; i < n; i++)
        if (!kw_cfstore_append(path, c->hdr[i].hash, c->filt[i].b, c->filt[i].n)) return 0;
    FILE *f = fopen(p2, "wb");
    if (!f) return 0;
    uint8_t buf[44]; memcpy(buf, "KWFH", 4);
    for (int i = 0; i < 8; i++) buf[4 + i] = (uint8_t)((uint64_t)n >> (8 * i));
    memcpy(buf + 12, c->fchain[n - 1], 32);
    fwrite(buf, 1, 44, f); fclose(f);
    return 1;
}

/* serve ops for blocks / cfheaders / cfilter; mutation byte (m): 0 honest */
static void nb_serve_block(nf_buf *out, uint32_t magic, const nb_chain *c, int b, uint8_t m, nf_in *in)
{
    nf_buf x = {0}; nb_put(&x, c->body[b].b, c->body[b].n);
    if (m & 1) { size_t at = in16(in) % x.n; x.b[at] ^= (uint8_t)(1 + in8(in) % 255); }
    if (m & 2) { x.n = in16(in) % (x.n + 1); }
    if (m & 4) { size_t g; const uint8_t *e = intake(in, in8(in) % 64, &g); nb_put(&x, e, g); }
    nf_frame(out, magic, "block", x.b, x.n, 1, 0, 0);
    nb_free(&x);
}
static void nb_serve_cfheaders(nf_buf *out, uint32_t magic, const nb_chain *c, int s0, int s1, uint8_t m, nf_in *in)
{
    if (s0 < 0) s0 = 0; if (s1 > c->nb) s1 = c->nb; if (s1 <= s0) s1 = s0 + 1 <= c->nb ? s0 + 1 : s0;
    nf_buf x = {0};
    nb_u8(&x, (m & 8) ? in8(in) : 0);
    nb_put(&x, c->hdr[s1 > 0 ? s1 - 1 : 0].hash, 32);
    uint8_t z[32] = {0};
    nb_put(&x, s0 ? c->fchain[s0 - 1] : z, 32);
    nb_varint(&x, (uint64_t)(s1 - s0));
    for (int i = s0; i < s1; i++) nb_put(&x, c->fhash[i], 32);
    if (m & 1) { size_t at = in16(in) % x.n; x.b[at] ^= (uint8_t)(1 + in8(in) % 255); }
    if (m & 2) x.n = in16(in) % (x.n + 1);
    nf_frame(out, magic, "cfheaders", x.b, x.n, 1, 0, 0);
    nb_free(&x);
}
static void nb_serve_cfilter(nf_buf *out, uint32_t magic, const nb_chain *c, int b, uint8_t m, nf_in *in)
{
    nf_buf x = {0};
    nb_u8(&x, 0);
    nb_put(&x, c->hdr[b].hash, 32);
    nb_varint(&x, c->filt[b].n);
    nb_put(&x, c->filt[b].b, c->filt[b].n);
    if (m & 1) { size_t at = in16(in) % x.n; x.b[at] ^= (uint8_t)(1 + in8(in) % 255); }
    if (m & 2) x.n = in16(in) % (x.n + 1);
    nf_frame(out, magic, "cfilter", x.b, x.n, 1, 0, 0);
    nb_free(&x);
}
#endif
