/* koinu.dog - BIP157 message tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * The getcfilters/cfilter wire format, plus an end-to-end check that a real
 * BIP158 filter wrapped in a cfilter message parses and matches its element. */

#include "cf.h"
#include "gcs.h"
#include "proto.h"
#include "peer.h"
#include "chainparams.h"
#include "sha2.h"
#include "testutil.h"

#include "bip158_vectors.h"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* frame (cmd,payload) and write it to the fake peer's end */
static int put_msg(int fd, uint32_t magic, const char *cmd, const uint8_t *pl, size_t pn)
{
    uint8_t frame[2048];
    size_t fn = kw_msg_serialize(magic, cmd, pl, pn, frame, sizeof frame);
    return fn && write(fd, frame, fn) == (ssize_t)fn;
}

static size_t mk_cfheaders(uint8_t *out, const uint8_t stop[32], const uint8_t prev[32],
                           const uint8_t fhash[32])
{
    out[0] = KW_CF_TYPE_BASIC;
    memcpy(out + 1, stop, 32);
    memcpy(out + 33, prev, 32);
    out[65] = 1;
    memcpy(out + 66, fhash, 32);
    return 98;
}

static size_t mk_cfilter(uint8_t *out, const uint8_t bh[32], const uint8_t *f, size_t flen)
{
    out[0] = KW_CF_TYPE_BASIC;
    memcpy(out + 1, bh, 32);
    out[33] = (uint8_t)flen;
    memcpy(out + 34, f, flen);
    return 34 + flen;
}

static void hex_rev(const uint8_t in[32], char out[65])
{
    static const char d[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[2 * i] = d[in[31 - i] >> 4];
        out[2 * i + 1] = d[in[31 - i] & 15];
    }
    out[64] = 0;
}

/* one uncached kw_cf_sync run against a preloaded socketpair peer */
static long cf_round(const kw_chainparams *cp, const kw_headerstore *s,
                     const uint8_t *msgs, const size_t *lens, const char **cmds, int nmsg)
{
    uint32_t magic = KW_DOGE_REGTEST.magic;
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return -2;
    struct timeval tv = { 5, 0 };
    setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    size_t off = 0;
    for (int i = 0; i < nmsg; i++) {
        if (!put_msg(sv[1], magic, cmds[i], msgs + off, lens[i])) { close(sv[0]); close(sv[1]); return -2; }
        off += lens[i];
    }
    kw_peer p;
    kw_peer_from_fd(&p, magic, sv[0]);
    p.cp = cp;
    kw_utxoset us; kw_utxoset_init(&us);
    kw_watchset ws; kw_watchset_init(&ws);      /* nothing watched: no block is fetched */
    long r = kw_cf_sync(&p, s, &us, &ws, 1);
    kw_watchset_free(&ws);
    kw_utxoset_free(&us);
    kw_peer_close(&p);
    close(sv[1]);
    return r;
}

int main(void)
{
    /* getcfilters: type, start height (LE), stop hash */
    {
        uint8_t stop[32];
        for (int i = 0; i < 32; i++) stop[i] = (uint8_t)(i + 1);
        uint8_t out[37];
        size_t n = kw_msg_getcfilters_build(KW_CF_TYPE_BASIC, 0x01020304, stop, out, sizeof out);
        if (n != 37) { fprintf(stderr, "FAIL: getcfilters len %zu\n", n); return 1; }
        if (out[0] != 0x00 || out[1] != 0x04 || out[2] != 0x03 || out[3] != 0x02 || out[4] != 0x01) {
            fprintf(stderr, "FAIL: getcfilters head\n"); return 1;
        }
        if (memcmp(out + 5, stop, 32) != 0) { fprintf(stderr, "FAIL: getcfilters stop\n"); return 1; }
        if (kw_msg_getcfilters_build(0, 0, stop, out, 36) != 0) { fprintf(stderr, "FAIL: short cap\n"); return 1; }
    }

    /* cfilter round-trip using a real filter, and it matches its own element */
    {
        const kw_bip158_vec *v = &KW_BIP158_VECS[2];   /* h49291: 10 elements */
        uint8_t hash[32]; kw_test_unhex(v->hash_internal, hash);
        uint8_t filt[256]; int flen = kw_test_unhex(v->filter, filt);

        uint8_t msg[512]; size_t n = 0;
        msg[n++] = KW_CF_TYPE_BASIC;
        memcpy(msg + n, hash, 32); n += 32;
        msg[n++] = (uint8_t)flen;                       /* filter under 253 bytes */
        memcpy(msg + n, filt, (size_t)flen); n += (size_t)flen;

        uint8_t type, bh[32]; const uint8_t *pf; size_t pfl;
        if (!kw_msg_cfilter_parse(msg, n, &type, bh, &pf, &pfl)) { fprintf(stderr, "FAIL: cfilter parse\n"); return 1; }
        if (type != KW_CF_TYPE_BASIC || memcmp(bh, hash, 32) != 0 || pfl != (size_t)flen ||
            memcmp(pf, filt, pfl) != 0) { fprintf(stderr, "FAIL: cfilter fields\n"); return 1; }

        uint8_t elem[4096];
        int elen = kw_test_unhex(v->elems[0], elem);
        kw_gcs_item it = { elem, (size_t)elen };
        if (kw_gcs_match_any(pf, pfl, bh, &it, 1) != 1) { fprintf(stderr, "FAIL: cfilter no match\n"); return 1; }

        /* a truncated cfilter is rejected */
        if (kw_msg_cfilter_parse(msg, 20, &type, bh, &pf, &pfl)) { fprintf(stderr, "FAIL: short cfilter\n"); return 1; }
    }

    /* cfheaders: type, stop, previous filter header, then the filter hashes */
    {
        uint8_t stop[32], prev[32], h1[32], h2[32];
        memset(stop, 0xaa, 32); memset(prev, 0xbb, 32);
        memset(h1, 0x01, 32); memset(h2, 0x02, 32);
        uint8_t msg[130]; size_t n = 0;
        msg[n++] = KW_CF_TYPE_BASIC;
        memcpy(msg + n, stop, 32); n += 32;
        memcpy(msg + n, prev, 32); n += 32;
        msg[n++] = 2;
        memcpy(msg + n, h1, 32); n += 32;
        memcpy(msg + n, h2, 32); n += 32;

        uint8_t type, ps[32], pp[32]; const uint8_t *hs; size_t nh;
        if (!kw_msg_cfheaders_parse(msg, n, &type, ps, pp, &hs, &nh)) { fprintf(stderr, "FAIL: cfheaders parse\n"); return 1; }
        if (type != KW_CF_TYPE_BASIC || nh != 2 || memcmp(ps, stop, 32) != 0 ||
            memcmp(pp, prev, 32) != 0 || memcmp(hs, h1, 32) != 0 || memcmp(hs + 32, h2, 32) != 0) {
            fprintf(stderr, "FAIL: cfheaders fields\n"); return 1;
        }
        /* truncation and a count beyond the payload are rejected */
        if (kw_msg_cfheaders_parse(msg, n - 1, &type, ps, pp, &hs, &nh)) { fprintf(stderr, "FAIL: short cfheaders\n"); return 1; }
        msg[65] = 3;
        if (kw_msg_cfheaders_parse(msg, n, &type, ps, pp, &hs, &nh)) { fprintf(stderr, "FAIL: overlong count\n"); return 1; }
    }

    /* the filter-header chain step reproduces every official vector */
    for (size_t i = 0; i < sizeof KW_BIP158_VECS / sizeof KW_BIP158_VECS[0]; i++) {
        const kw_bip158_vec *v = &KW_BIP158_VECS[i];
        uint8_t filt[256]; int flen = kw_test_unhex(v->filter, filt);
        uint8_t prev[32], want[32]; kw_test_unhex(v->prev_header, prev); kw_test_unhex(v->header, want);
        uint8_t fhash[32], got[32];
        kw_hash256(filt, (size_t)flen, fhash);
        kw_cf_header_step(fhash, prev, got);
        if (memcmp(got, want, 32) != 0) { fprintf(stderr, "FAIL: header chain %s\n", v->name); return 1; }
    }

    /* The uncached path checks the anchors too. It used to be the cached store alone,
       which left the three call sites that never pass a filters path taking whatever
       chain base the peer offered. */
    {
        kw_block_header h1;
        uint8_t raw[80];
        memset(raw, 0, 80); raw[0] = 1;
        kw_block_header_parse(raw, 80, &h1);

        uint8_t f1[2] = { 0xaa, 0xbb };
        uint8_t prev0[32]; memset(prev0, 0x11, 32);
        uint8_t hash1[32], chain1[32];
        kw_hash256(f1, sizeof f1, hash1);
        kw_cf_header_step(hash1, prev0, chain1);

        uint8_t msgs[512]; size_t lens[2]; const char *cmds[2] = { "cfheaders", "cfilter" };
        lens[0] = mk_cfheaders(msgs, h1.hash, prev0, hash1);
        lens[1] = mk_cfilter(msgs + lens[0], h1.hash, f1, sizeof f1);

        kw_headerstore s; kw_headerstore_init(&s);
        kw_headerstore_append(&s, &h1);

        char good[65], bad[65];
        uint8_t other[32]; memset(other, 0x5a, 32);
        hex_rev(chain1, good);
        hex_rev(other, bad);

        kw_chainparams cpa = KW_DOGE_REGTEST;
        kw_cfcheckpoint anchor[1];
        cpa.cfcheckpoints = anchor; cpa.ncfcheckpoints = 1;
        anchor[0].height = 1;

        anchor[0].header = good;
        if (cf_round(&cpa, &s, msgs, lens, cmds, 2) != 0) {
            fprintf(stderr, "FAIL: uncached sync refused a chain matching the anchor\n");
            kw_headerstore_free(&s); return 1;
        }
        anchor[0].header = bad;
        if (cf_round(&cpa, &s, msgs, lens, cmds, 2) != -1) {
            fprintf(stderr, "FAIL: uncached sync accepted a chain contradicting the anchor\n");
            kw_headerstore_free(&s); return 1;
        }
        kw_headerstore_free(&s);
    }

    printf("cf ok: getcfilters format, cfilter round-trip, real-filter match, cfheaders parse, header chain vectors,\n  uncached sync anchored\n");
    return 0;
}
