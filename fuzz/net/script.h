/* netfuzz: the peer-script interpreter shared by the harnesses.
   A script is a sequence of ops read from the fuzz input; each op appends bytes
   to a peer's outgoing stream. Structured ops (headers, blocks, cfheaders, ...)
   are supplied by the harness through (structured). */
#ifndef NF_SCRIPT_H
#define NF_SCRIPT_H
#include "nf.h"

static const char *const nf_cmds[] = {
    "headers", "ping", "pong", "inv", "feefilter", "version", "verack", "block",
    "cfheaders", "cfilter", "getheaders", "addr", "sendheaders", "notfound", "reject", "tx",
};

/* the honest regtest chain every harness can refer to */
#define NF_HONEST 48
static uint8_t nf_honest_raw[NF_HONEST][80];
static uint8_t nf_honest_hash[NF_HONEST][32];
static uint8_t nf_gen[32];

static void nf_honest_init(const kw_chainparams *cp)
{
    nf_genesis(cp, nf_gen);
    const uint8_t *prev = nf_gen;
    for (int i = 0; i < NF_HONEST; i++) {
        uint8_t m[32]; memset(m, 0, 32); m[0] = (uint8_t)i; m[1] = 0xa5;
        nf_hdr_fill(nf_honest_raw[i], 1, prev, m, cp->genesis_time + 60u * (uint32_t)(i + 1), NF_EASY, 0);
        if (!nf_mine_cached(nf_honest_raw[i], 1)) abort();
        kw_hash256(nf_honest_raw[i], 80, nf_honest_hash[i]);
        prev = nf_honest_hash[i];
    }
}

typedef int (*nf_structured_fn)(void *ctx, nf_in *in, nf_peer *pp, int op);

/* Read up to (maxops) ops for one peer. Ops:
     0 raw frame     1..3 structured (harness-defined, op passed)   4 ping
     5 chunk cut     6 raw unframed bytes   7 end of this peer's script */
static void nf_script(nf_in *in, nf_peer *pp, uint32_t magic, int maxops,
                      nf_structured_fn st, void *ctx)
{
    for (int k = 0; k < maxops && in->n; k++) {
        uint8_t op = in8(in);
        switch (op & 7) {
        case 0: {
            uint8_t c = in8(in);
            char cmd[13] = {0};
            if (c & 0x80) { size_t g; const uint8_t *b = intake(in, 12, &g); memcpy(cmd, b, g); }
            else snprintf(cmd, sizeof cmd, "%s", nf_cmds[c % (sizeof nf_cmds / sizeof *nf_cmds)]);
            uint16_t ln = in16(in) % 4096;
            size_t g; const uint8_t *b = intake(in, ln, &g);
            int fix = !(op & 0x80);
            uint32_t bl = fix ? 0 : in32(in), bc = fix ? 0 : in32(in);
            nf_frame(&pp->script, magic, cmd, b, g, fix, bl, bc);
            break;
        }
        case 1: case 2: case 3:
            if (st && !st(ctx, in, pp, op)) return;
            break;
        case 4: { uint8_t n[8]; for (int i = 0; i < 8; i++) n[i] = in8(in); nf_frame(&pp->script, magic, "ping", n, 8, 1, 0, 0); break; }
        case 5: nf_peer_cut(pp); break;
        case 6: { size_t g; const uint8_t *b = intake(in, in8(in) % 64, &g); nb_put(&pp->script, b, g); break; }
        case 7: return;
        }
    }
}

/* A headers message built from the fuzz input. (base) is the parent hash of the
   first header; (out_tip) gets the last header's hash. Each header: a flag byte
   (bit0 mine good, bit1 mine bad, bit2 hard bits, bit3 fuzzed bits, bit4 auxpow
   version bit with a fuzzed blob, bit5 break the prev link, bit6 fuzzed time,
   bit7 honest header at this height when available), a merkle seed. */
static size_t nf_headers_msg(nf_in *in, nf_buf *pl, const uint8_t base[32], uint32_t base_height,
                             int maxn, uint8_t out_tip[32], uint32_t t0)
{
    int n = in8(in) % (maxn + 1);
    nb_varint(pl, (uint64_t)n);
    uint8_t prev[32]; memcpy(prev, base, 32);
    for (int i = 0; i < n; i++) {
        uint8_t f = in8(in);
        uint32_t h = base_height + 1 + (uint32_t)i;
        uint8_t raw[80];
        if ((f & 0x80) && h >= 1 && h <= NF_HONEST && !memcmp(prev, h == 1 ? nf_gen : nf_honest_hash[h - 2], 32)) {
            memcpy(raw, nf_honest_raw[h - 1], 80);
        } else {
            uint8_t m[32]; memset(m, 0, 32); m[0] = in8(in); m[1] = in8(in); m[31] = 0x5a;
            uint32_t bits = (f & 4) ? NF_HARD : NF_EASY;
            if (f & 8) bits = in32(in);
            uint32_t ver = (f & 0x10) ? 0x00620104u : 0x00620004u;
            uint32_t tm = (f & 0x40) ? in32(in) : t0 + 60u * h;
            uint8_t pv[32]; memcpy(pv, prev, 32);
            if (f & 0x20) pv[in8(in) & 31] ^= 1 + in8(in) % 255;
            nf_hdr_fill(raw, ver, pv, m, tm, bits, 0);
            if (f & 1) nf_mine_cached(raw, 1);
            else if (f & 2) nf_mine_cached(raw, 0);
        }
        nb_put(pl, raw, 80);
        if (raw[1] & 0x01) {                     /* auxpow blob, fuzzed, length-capped */
            size_t g; const uint8_t *b = intake(in, in8(in), &g);
            nb_put(pl, b, g);
        }
        nb_u8(pl, 0);                            /* tx count */
        kw_hash256(raw, 80, prev);
    }
    memcpy(out_tip, prev, 32);
    return (size_t)n;
}
#endif
