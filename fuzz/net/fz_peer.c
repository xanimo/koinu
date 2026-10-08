/* netfuzz target 5: kw_peer_handshake and kw_peer_recv buffering over a byte
   stream written in fuzzer-chosen chunks.

   input: [cfg][script ops...]   cfg bit0: run the handshake first

   Oracle: the harness re-parses its own stream with an independent framer and
   predicts the exact sequence kw_peer_recv must return:
     each whole frame with right magic, length <= 32 MiB and checksum -> 1 with
       that command and payload, except feefilter with >= 8 bytes, which is
       consumed silently and sets peer_feerate
     the first bad frame -> -1;  a partial frame at the end -> 0 (EOF)
   P1 every returned message matches the prediction, in order
   P2 the terminal return code matches
   P3 peer_feerate equals the last feefilter value consumed before the stop
   P4 handshake returns 1 iff a verack frame arrives before the first bad frame
      (and the library then continues from the frame after that verack) */
#include "script.h"
#include <signal.h>

static const kw_chainparams *CP = &KW_DOGE_REGTEST;

typedef struct { char cmd[13]; size_t off, len; } pmsg;

int LLVMFuzzerInitialize(int *argc, char ***argv) { (void)argc; (void)argv; signal(SIGPIPE, SIG_IGN); return 0; }

static int st_peer(void *v, nf_in *in, nf_peer *pp, int op)
{
    (void)v;
    switch (op & 3) {
    case 1: {                                   /* a version message, fuzzed fields */
        nf_buf b = {0};
        nb_le32(&b, in32(in)); nb_le64(&b, in64(in)); nb_le64(&b, in64(in));
        for (int i = 0; i < 26 * 2; i++) nb_u8(&b, in8(in));
        nb_le64(&b, in64(in));
        size_t g; const uint8_t *ua = intake(in, in8(in) % 40, &g);
        nb_varint(&b, g); nb_put(&b, ua, g);
        nb_le32(&b, in32(in));
        if (in8(in) & 1) nb_u8(&b, 0);
        if (in8(in) & 1) b.n = in8(in) % (b.n + 1);
        nf_frame(&pp->script, CP->magic, "version", b.b, b.n, 1, 0, 0);
        nb_free(&b);
        break; }
    case 2: nf_frame(&pp->script, CP->magic, "verack", NULL, 0, 1, 0, 0); break;
    case 3: {                                   /* feefilter, short or 8 bytes */
        uint8_t f[8]; for (int i = 0; i < 8; i++) f[i] = in8(in);
        nf_frame(&pp->script, CP->magic, "feefilter", f, (in8(in) & 1) ? 8 : in8(in) % 9, 1, 0, 0);
        break; }
    }
    return 1;
}

static uint32_t le32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) return 0;
    nf_in in = { data, size };
    uint8_t cfg = in8(&in);
    nf_peer pp; kw_peer lp; memset(&pp, 0, sizeof pp);
    nf_peer_open(&pp, &lp, CP);
    nf_script(&in, &pp, CP->magic, 48, st_peer, NULL);

    /* predict */
    pmsg *ex = (pmsg *)calloc(256, sizeof *ex); int nex = 0, term = 0;
    int64_t fee_after[257]; int64_t fee = 0;
    const uint8_t *S = pp.script.b; size_t N = pp.script.n, o = 0;
    for (;;) {
        if (N - o < 24) { term = 0; break; }
        if (le32(S + o) != CP->magic) { term = -1; break; }
        uint32_t L = le32(S + o + 16);
        if (L > 32u * 1024 * 1024) { term = -1; break; }
        if (N - o - 24 < L) { term = 0; break; }
        uint8_t d[32]; kw_hash256(S + o + 24, L, d);
        if (memcmp(d, S + o + 20, 4)) { term = -1; break; }
        char cmd[13]; memcpy(cmd, S + o + 4, 12); cmd[12] = 0;
        if (!strcmp(cmd, "feefilter") && L >= 8) {
            /* assembled unsigned and clamped, which is what kw_peer_recv does: a
               top byte of 0x80 or more is undefined in a signed shift, and a peer
               picks that byte. The model said "sign-extend" while the library was
               fixed, so this invariant was asserting the old behaviour. */
            uint64_t fr = 0;
            for (int i = 0; i < 8; i++) fr |= (uint64_t)S[o + 24 + i] << (8 * i);
            fee = fr > (uint64_t)INT64_MAX ? INT64_MAX : (int64_t)fr;
        } else if (nex < 256) {
            memcpy(ex[nex].cmd, cmd, 13); ex[nex].off = o + 24; ex[nex].len = L;
            fee_after[nex] = fee; nex++;
        } else break;
        o += 24 + L;
    }
    if (nex == 256) term = 2;                   /* do not predict past the cap */

    nf_peer_start(&pp);
    int i = 0;
    if (cfg & 1) {
        int hv = -1;
        for (int k = 0; k < nex; k++) if (!strcmp(ex[k].cmd, "verack")) { hv = k; break; }
        int hasver = 0;
        for (int k = 0; k < hv; k++) if (!strcmp(ex[k].cmd, "version")) hasver = 1;
        int r = kw_peer_handshake(&lp, 0);
        if (r != (hv >= 0 && hasver)) NF_FAIL("P4 handshake %d, verack at %d of %d (term %d)", r, hv, nex, term);
        if (hv >= 0) i = hv + 1;
        else goto done;
    }
    for (; i < nex; i++) {
        char cmd[13]; const uint8_t *pl = NULL; size_t pn = 0;
        int r = kw_peer_recv(&lp, cmd, &pl, &pn);
        if (r != 1) NF_FAIL("P1 message %d of %d: recv %d", i, nex, r);
        if (strcmp(cmd, ex[i].cmd) || pn != ex[i].len || (pn && memcmp(pl, S + ex[i].off, pn)))
            NF_FAIL("P1 message %d: got %s/%zu want %s/%zu", i, cmd, pn, ex[i].cmd, ex[i].len);
        if (lp.peer_feerate != fee_after[i]) NF_FAIL("P3 feerate %lld want %lld at %d", (long long)lp.peer_feerate, (long long)fee_after[i], i);
    }
    if (term != 2) {
        char cmd[13]; const uint8_t *pl = NULL; size_t pn = 0;
        int r = kw_peer_recv(&lp, cmd, &pl, &pn);
        if (r != term) NF_FAIL("P2 terminal recv %d want %d after %d messages", r, term, nex);
        if (lp.peer_feerate != fee) NF_FAIL("P3 final feerate %lld want %lld", (long long)lp.peer_feerate, (long long)fee);
    }
done:
    kw_peer_close(&lp);
    nf_peer_finish(&pp);
    free(ex);
    return 0;
}
