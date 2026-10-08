/* netfuzz target 1: kw_sync_headers_best with 1-3 scripted peers, from an empty
   or pre-loaded store, on regtest params (optionally a copy carrying anchors).

   input: [cfg][pre][powsel][peer scripts...]
   cfg: bits0-1 npeers-1 (0..2, 3->1), bit2 anchored params copy, bit3 preload
        a fork tail instead of the honest prefix
   pre: number of honest headers preloaded (mod NF_HONEST-8)

   Invariants after the call:
   I1 every header links to its predecessor (genesis for height 1) and its stored
      hash is sha256d(raw)
   I2 every header at or above the effective pow_from that was not in the
      starting store satisfies its own target
   I3 the store is not shorter than it began unless a heavier chain replaced it
      (the documented reorg case), and its tail work never drops
   I4 on -1 the store equals its starting contents (finding 11 for npeers==1:
      reported once, then disabled; kept on for npeers>1)
   I5 the return value equals headers appended above the fork */
#include "script.h"
#include "chainsel.h"
#include "sync.h"
#include <signal.h>
/* kw_header_version lives in net/pow.h now */

static kw_chainparams CP_PLAIN, CP_ANCH;
static kw_checkpoint anch[3];
static char anch_hex[3][65];
static int known11;

struct pctx { uint8_t cur[32]; uint32_t h; uint32_t magic; nf_buf last; };

static int st_sync(void *v, nf_in *in, nf_peer *pp, int op)
{
    struct pctx *c = (struct pctx *)v;
    nf_buf pl = {0};
    if ((op & 3) == 1) {                       /* continue this peer's chain */
        uint8_t tip[32];
        size_t n = nf_headers_msg(in, &pl, c->cur, c->h, 12, tip, CP_PLAIN.genesis_time);
        memcpy(c->cur, tip, 32); c->h += (uint32_t)n;
    } else if ((op & 3) == 2) {                /* nothing after your tip, or repeat the last */
        if ((in8(in) & 1) && c->last.n) nb_put(&pl, c->last.b, c->last.n);
        else nb_u8(&pl, 0);
    } else {                                   /* restart from an honest height: a fork */
        uint32_t at = in8(in) % (NF_HONEST + 1);
        memcpy(c->cur, at ? nf_honest_hash[at - 1] : nf_gen, 32); c->h = at;
        uint8_t tip[32];
        size_t n = nf_headers_msg(in, &pl, c->cur, c->h, 12, tip, CP_PLAIN.genesis_time + 7);
        memcpy(c->cur, tip, 32); c->h += (uint32_t)n;
    }
    nf_frame(&pp->script, c->magic, "headers", pl.b, pl.n, 1, 0, 0);
    if (pl.n > 1) { c->last.n = 0; nb_put(&c->last, pl.b, pl.n); }
    nb_free(&pl);
    return 1;
}

static void work_of(const kw_headerstore *s, uint32_t from, kw_u256 *w)
{
    kw_u256_zero(w);
    for (uint32_t h = from + 1; h <= s->count; h++) {
        kw_u256 x;
        if (kw_bits_work(kw_header_bits(s->h[h - 1].raw), &x)) kw_u256_add(w, &x);
    }
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    CP_PLAIN = KW_DOGE_REGTEST;
    nf_honest_init(&CP_PLAIN);
    CP_ANCH = KW_DOGE_REGTEST;
    anch[0].height = 0; snprintf(anch_hex[0], 65, "%s", KW_DOGE_REGTEST.genesis);
    anch[1].height = 8; nf_hex_rev(nf_honest_hash[7], anch_hex[1]);
    anch[2].height = 16; nf_hex_rev(nf_honest_hash[15], anch_hex[2]);
    for (int i = 0; i < 3; i++) anch[i].hash = anch_hex[i];
    CP_ANCH.checkpoints = anch; CP_ANCH.ncheckpoints = 3;
    signal(SIGPIPE, SIG_IGN);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 3) return 0;
    nf_in in = { data, size };
    uint8_t cfg = in8(&in), pre = in8(&in), powsel = in8(&in);
    int npeers = (cfg & 3) == 3 ? 1 : (cfg & 3) + 1;
    const kw_chainparams *cp = (cfg & 4) ? &CP_ANCH : &CP_PLAIN;

    kw_headerstore s; kw_headerstore_init(&s);
    uint32_t k = pre % (NF_HONEST - 8);
    for (uint32_t i = 0; i < k; i++) {
        kw_block_header h; kw_block_header_parse(nf_honest_raw[i], 80, &h);
        kw_headerstore_append(&s, &h);
    }
    if ((cfg & 8) && k) {                      /* a mined fork tail on top */
        uint32_t extra = 1 + (pre >> 6);
        uint8_t prev[32]; memcpy(prev, s.h[s.count - 1].hash, 32);
        for (uint32_t i = 0; i < extra; i++) {
            uint8_t raw[80], m[32]; memset(m, 0xee, 32); m[0] = (uint8_t)i;
            nf_hdr_fill(raw, 1, prev, m, CP_PLAIN.genesis_time + 99, NF_EASY, 0);
            nf_mine_cached(raw, 1);
            kw_block_header h; kw_block_header_parse(raw, 80, &h);
            kw_headerstore_append(&s, &h);
            memcpy(prev, h.hash, 32);
        }
    }
    size_t start_n = s.count;
    kw_block_header *start = (kw_block_header *)malloc((start_n ? start_n : 1) * sizeof *start);
    memcpy(start, s.h, start_n * sizeof *start);

    uint32_t pow_from;
    switch (powsel & 3) {
    case 0: pow_from = 1; break;
    case 1: pow_from = (uint32_t)start_n + 1; break;
    case 2: pow_from = (uint32_t)start_n + 1 + (powsel >> 2) % 8; break;
    default: pow_from = (powsel >> 2) % 20; break;
    }

    nf_peer pp[3]; kw_peer lp[3]; kw_peer *lpp[3];
    struct pctx pc[3];
    memset(pp, 0, sizeof pp);
    for (int i = 0; i < npeers; i++) {
        nf_peer_open(&pp[i], &lp[i], cp);
        lpp[i] = &lp[i];
        memcpy(pc[i].cur, start_n ? s.h[start_n - 1].hash : nf_gen, 32);
        pc[i].h = (uint32_t)start_n; pc[i].magic = cp->magic; memset(&pc[i].last, 0, sizeof pc[i].last);
        nf_script(&in, &pp[i], cp->magic, 24, st_sync, &pc[i]);
    }
    for (int i = 0; i < npeers; i++) nf_peer_start(&pp[i]);

    kw_chainsel_result r;
    long ret = kw_sync_headers_best(lpp, npeers, &s, cp, pow_from, &r);

    for (int i = 0; i < npeers; i++) { kw_peer_close(&lp[i]); nf_peer_finish(&pp[i]); nb_free(&pc[i].last); }

    if (getenv("NF_DEBUG")) fprintf(stderr, "np=%d start=%zu ret=%ld count=%zu winner=%d ncand=%d fork=%u bad=%u checked=%llu pow_from=%u\n", npeers, start_n, ret, s.count, r.winner, r.ncandidates, r.fork_height, r.bad_height, (unsigned long long)r.pow_checked, pow_from);
    /* I1 */
    size_t bad = 0;
    if (!nf_store_links(&s, nf_gen, &bad)) NF_FAIL("I1 store does not link at height %zu", bad);

    /* where the new headers start: the first height that differs from the start */
    size_t same = 0;
    while (same < start_n && same < s.count && !memcmp(start[same].hash, s.h[same].hash, 32)) same++;

    /* I4 */
    if (ret < 0) {
        int eq = s.count == start_n && same == start_n;
        if (!eq) {
            if (npeers == 1) { nf_known("finding 11: single-peer -1 leaves the store changed", &known11); }
            else NF_FAIL("I4 multi-peer -1 changed the store: %zu -> %zu, same prefix %zu", start_n, s.count, same);
        }
    }

    /* I2: effective pow_from as the library computes it */
    uint32_t eff = pow_from;
    if (npeers > 1) {
        uint32_t floor = 0;
        for (size_t i = 0; i < cp->ncheckpoints; i++) {
            uint32_t h = cp->checkpoints[i].height;
            if (h && h <= start_n && h > floor) floor = h;
        }
        if (eff > floor + 1) eff = floor + 1;
        if (start_n - floor > 200000) eff = pow_from;
    }
    if (ret >= 0) {
        for (size_t i = same; i < s.count; i++) {
            uint32_t h = (uint32_t)i + 1;
            if (h < eff) continue;
            if (kw_header_version(s.h[i].raw) & 0x100) continue;   /* work is the parent's */
            if (!nf_pow_ok_cached(s.h[i].raw))
                NF_FAIL("I2 height %u (pow_from %u, eff %u, npeers %d) fails its target", h, pow_from, eff, npeers);
        }
        /* I3 */
        if (s.count < start_n) {
            kw_u256 a, b; work_of(&s, (uint32_t)same, &a);
            kw_headerstore tmp = { start, start_n, start_n };
            work_of(&tmp, (uint32_t)same, &b);
            if (kw_u256_cmp(&a, &b) <= 0) NF_FAIL("I3 store shrank %zu -> %zu without more work", start_n, s.count);
        }
        /* I5 */
        if (npeers == 1 && (size_t)ret != s.count - start_n) NF_FAIL("I5 ret %ld but grew %zu -> %zu", ret, start_n, s.count);
        if (npeers > 1 && r.winner >= 0 && (size_t)ret != s.count - r.fork_height)
            NF_FAIL("I5 ret %ld, count %zu, fork %u", ret, s.count, r.fork_height);
    }

    free(start);
    kw_headerstore_free(&s);
    return 0;
}
