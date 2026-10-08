/* netfuzz target 4: kw_psync_segment with a scripted per-segment peer, over a
   window of the honest regtest chain: (start, end] with start/end chosen by the
   input, the start hash the honest one, the end hash the honest one (or, bit,
   a fuzzed one so a forged segment can be asked to verify).

   S1 on 1: the buffer holds end-start KWH2 records, each record's hash field is
      sha256d of its raw header, each raw header links to the previous record
      (the first to start_hash), and the last record's hash equals end_hash
   S2 with the honest end hash, 1 implies the records are the honest headers
      (a second preimage of sha256d would be needed otherwise)
   S3 the getheaders the library sends always carry end_hash as stop */
#include "script.h"
#include "psync.h"
#include "msg.h"
#include <signal.h>

static const kw_chainparams *CP = &KW_DOGE_REGTEST;

struct sctx { uint8_t cur[32]; uint32_t h; };

static int st_seg(void *v, nf_in *in, nf_peer *pp, int op)
{
    struct sctx *c = (struct sctx *)v;
    nf_buf pl = {0};
    if ((op & 3) == 3) {                         /* restart the served chain at an honest height */
        uint32_t at = in8(in) % (NF_HONEST + 1);
        memcpy(c->cur, at ? nf_honest_hash[at - 1] : nf_gen, 32); c->h = at;
        return 1;
    }
    if ((op & 3) == 2) nb_u8(&pl, 0);
    else {
        uint8_t tip[32];
        size_t n = nf_headers_msg(in, &pl, c->cur, c->h, 20, tip, CP->genesis_time);
        memcpy(c->cur, tip, 32); c->h += (uint32_t)n;
    }
    nf_frame(&pp->script, CP->magic, "headers", pl.b, pl.n, 1, 0, 0);
    nb_free(&pl);
    return 1;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    nf_honest_init(CP);
    signal(SIGPIPE, SIG_IGN);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 3) return 0;
    nf_in in = { data, size };
    uint8_t a = in8(&in), b = in8(&in), cfg = in8(&in);
    uint32_t start = a % (NF_HONEST - 1);
    uint32_t end = start + 1 + b % (NF_HONEST - start);
    if (end > NF_HONEST) end = NF_HONEST;
    uint8_t sh[32], eh[32];
    memcpy(sh, start ? nf_honest_hash[start - 1] : nf_gen, 32);
    int honest_end = !(cfg & 1);
    if (honest_end) memcpy(eh, nf_honest_hash[end - 1], 32);
    else for (int i = 0; i < 32; i++) eh[i] = in8(&in);

    nf_peer pp; kw_peer lp; memset(&pp, 0, sizeof pp);
    nf_peer_open(&pp, &lp, CP);
    pp.record = 1;
    struct sctx sc; memcpy(sc.cur, sh, 32); sc.h = start;
    nf_script(&in, &pp, CP->magic, 32, st_seg, &sc);
    nf_peer_start(&pp);

    size_t nrec = end - start;
    uint8_t *out = (uint8_t *)malloc(nrec * KW_HDR_REC);
    memset(out, 0xcd, nrec * KW_HDR_REC);
    int r = kw_psync_segment(&lp, out, sh, start, eh, end);
    if (getenv("NF_DEBUG")) fprintf(stderr, "seg %u..%u honest_end %d r=%d\n", start, end, honest_end, r);
    kw_peer_close(&lp);
    /* S3 needs what was sent: join first, then take the record */
    if (pp.started) { pthread_join(pp.th, NULL); pp.started = 0; }
    nf_buf got = pp.got; pp.got.b = NULL; pp.got.n = pp.got.cap = 0;
    nf_peer_finish(&pp);

    if (r == 1) {
        const uint8_t *prev = sh;
        for (size_t i = 0; i < nrec; i++) {
            const uint8_t *rec = out + i * KW_HDR_REC;
            uint8_t h[32]; kw_hash256(rec, 80, h);
            if (memcmp(h, rec + 80, 32)) NF_FAIL("S1 record %zu hash field is not sha256d(raw)", i);
            if (memcmp(rec + 4, prev, 32)) NF_FAIL("S1 record %zu does not link", i);
            prev = rec + 80;
        }
        if (memcmp(prev, eh, 32)) NF_FAIL("S1 last record is not end_hash");
        if (honest_end)
            for (size_t i = 0; i < nrec; i++)
                if (memcmp(out + i * KW_HDR_REC, nf_honest_raw[start + i], 80))
                    NF_FAIL("S2 record %zu differs from the honest header", i);
    }
    /* S3: every getheaders frame's last 32 bytes are the stop hash */
    for (size_t o = 0; o + 24 <= got.n; ) {
        uint32_t L = (uint32_t)got.b[o + 16] | (uint32_t)got.b[o + 17] << 8 | (uint32_t)got.b[o + 18] << 16 | (uint32_t)got.b[o + 19] << 24;
        if (o + 24 + L > got.n) break;
        if (!memcmp(got.b + o + 4, "getheaders", 10) && (L < 32 || memcmp(got.b + o + 24 + L - 32, eh, 32)))
            NF_FAIL("S3 getheaders without the stop hash");
        o += 24 + L;
    }
    nb_free(&got);
    free(out);
    return 0;
}
