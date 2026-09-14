/* koinu.dog - filter cache tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Append two real BIP158 filters to a cache file, then confirm count, that a
 * matching element is found at its block index, and that an unrelated script
 * is not. Header integrity is exercised by the live path, so (s) is NULL here. */

#include "cfstore.h"
#include "cf.h"
#include "gcs.h"
#include "sha2.h"
#include "proto.h"
#include "peer.h"
#include "chainparams.h"
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

/* the <path>.fh sidecar, written by hand: the tests need to damage it */
static int fh_peek(const char *path, long *count)
{
    char fp[64]; snprintf(fp, sizeof fp, "%s.fh", path);
    FILE *f = fopen(fp, "rb");
    if (!f) return 0;
    uint8_t b[44];
    int ok = fread(b, 1, sizeof b, f) == sizeof b;
    fclose(f);
    if (!ok) return 0;
    *count = 0;
    for (int i = 0; i < 8; i++) *count |= (long)b[4 + i] << (8 * i);
    return 1;
}

static int fh_poke(const char *path, long count, const uint8_t hdr[32])
{
    char fp[64]; snprintf(fp, sizeof fp, "%s.fh", path);
    FILE *f = fopen(fp, "wb");
    if (!f) return 0;
    uint8_t b[44];
    memcpy(b, "KWFH", 4);
    for (int i = 0; i < 8; i++) b[4 + i] = (uint8_t)((uint64_t)count >> (8 * i));
    memcpy(b + 12, hdr, 32);
    int ok = fwrite(b, 1, sizeof b, f) == sizeof b;
    fclose(f);
    return ok;
}

/* one kw_cfstore_sync run against a preloaded socketpair peer */
static long sync_round_cp(const kw_chainparams *cp, const kw_headerstore *s, const char *path,
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
    p.cp = cp;                       /* NULL: no anchors, as from_fd leaves it */
    long r = kw_cfstore_sync(&p, s, path, 1);
    kw_peer_close(&p);
    close(sv[1]);
    return r;
}

static long sync_round(const kw_headerstore *s, const char *path,
                       const uint8_t *msgs, const size_t *lens, const char **cmds, int nmsg)
{
    return sync_round_cp(NULL, s, path, msgs, lens, cmds, nmsg);
}

/* internal-order bytes to the display (reversed) hex a checkpoint table holds */
static void hex_rev(const uint8_t v[32], char out[65])
{
    static const char *D = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[2 * i]     = D[v[31 - i] >> 4];
        out[2 * i + 1] = D[v[31 - i] & 15];
    }
    out[64] = 0;
}

int main(void)
{
    const char *tmp = "test_cfstore.tmp";
    remove(tmp);

    const kw_bip158_vec *a = &KW_BIP158_VECS[2];   /* h49291, 10 elems */
    const kw_bip158_vec *b = &KW_BIP158_VECS[3];   /* h180480, 13 elems */

    uint8_t ha[32], hb[32], fa[256], fb[256];
    kw_test_unhex(a->hash_internal, ha); kw_test_unhex(b->hash_internal, hb);
    int fal = kw_test_unhex(a->filter, fa), fbl = kw_test_unhex(b->filter, fb);

    if (!kw_cfstore_append(tmp, ha, fa, (size_t)fal) ||
        !kw_cfstore_append(tmp, hb, fb, (size_t)fbl)) { fprintf(stderr, "FAIL: append\n"); return 1; }
    if (kw_cfstore_count(tmp) != 2) { fprintf(stderr, "FAIL: count\n"); return 1; }

    /* an element of the first filter is found at index 0 */
    uint8_t elem[4096];
    int elen = kw_test_unhex(a->elems[0], elem);
    kw_gcs_item it = { elem, (size_t)elen };
    uint32_t heights[8];
    long n = kw_cfstore_match(tmp, NULL, 0, &it, 1, heights, 8);
    if (n < 1 || heights[0] != 0) { fprintf(stderr, "FAIL: match (n=%ld)\n", n); return 1; }

    /* an unrelated p2pkh script matches nothing */
    uint8_t bogus[25];
    memset(bogus, 0, sizeof bogus); bogus[0] = 0x76; bogus[1] = 0xa9; bogus[2] = 0x14;
    for (int i = 0; i < 20; i++) bogus[3 + i] = (uint8_t)(0x40 + i);
    bogus[23] = 0x88; bogus[24] = 0xac;
    kw_gcs_item bit = { bogus, sizeof bogus };
    if (kw_cfstore_match(tmp, NULL, 0, &bit, 1, heights, 8) != 0) { fprintf(stderr, "FAIL: false positive\n"); return 1; }

    /* range: from height 1 skips index 0, so b's element matches at 1 and a's
       does not (it lives at index 0, before the range) */
    uint8_t eb[4096];
    int ebl = kw_test_unhex(b->elems[0], eb);
    kw_gcs_item bt = { eb, (size_t)ebl };
    long r = kw_cfstore_match_range(tmp, NULL, 0, 1, &bt, 1, heights, 8);
    if (r < 1 || heights[0] != 1) { fprintf(stderr, "FAIL: range match b (r=%ld)\n", r); return 1; }
    if (kw_cfstore_match_range(tmp, NULL, 0, 1, &it, 1, heights, 8) != 0) { fprintf(stderr, "FAIL: range skipped a\n"); return 1; }

    /* a corrupt tag is rejected */
    FILE *f = fopen(tmp, "r+b"); if (f) { fputc('X', f); fclose(f); }
    if (kw_cfstore_count(tmp) != -1) { fprintf(stderr, "FAIL: corrupt tag accepted\n"); return 1; }
    remove(tmp);
    remove("test_cfstore.tmp.idx");

    /* sync verifies the cfheaders commitment chain and pins its tip in <path>.fh */
    {
        const char *sp = "test_cfstore_sync.tmp";
        remove(sp);
        char aux[64];
        snprintf(aux, sizeof aux, "%s.idx", sp); remove(aux);
        snprintf(aux, sizeof aux, "%s.fh", sp);  remove(aux);

        /* three linked headers, base height 1 */
        kw_block_header h1, h2, h3;
        uint8_t raw[80];
        memset(raw, 0, 80); raw[0] = 1;
        kw_block_header_parse(raw, 80, &h1);
        memset(raw, 0, 80); raw[0] = 2; memcpy(raw + 4, h1.hash, 32);
        kw_block_header_parse(raw, 80, &h2);
        memset(raw, 0, 80); raw[0] = 3; memcpy(raw + 4, h2.hash, 32);
        kw_block_header_parse(raw, 80, &h3);

        uint8_t f1[2] = { 0xaa, 0xbb }, f2[1] = { 0xcc }, f3[1] = { 0xdd };
        uint8_t prev0[32]; memset(prev0, 0x11, 32);
        uint8_t hash1[32], hash2[32], hash3[32], chain1[32], chain2[32];
        kw_hash256(f1, sizeof f1, hash1);
        kw_hash256(f2, sizeof f2, hash2);
        kw_hash256(f3, sizeof f3, hash3);
        kw_cf_header_step(hash1, prev0, chain1);
        kw_cf_header_step(hash2, chain1, chain2);

        uint8_t msgs[512]; size_t lens[2]; const char *cmds[2] = { "cfheaders", "cfilter" };
        kw_headerstore s; kw_headerstore_init(&s);
        kw_headerstore_append(&s, &h1);

        /* first fill adopts the peer's chain base and caches the filter */
        lens[0] = mk_cfheaders(msgs, h1.hash, prev0, hash1);
        lens[1] = mk_cfilter(msgs + lens[0], h1.hash, f1, sizeof f1);
        if (sync_round(&s, sp, msgs, lens, cmds, 2) != 1) { fprintf(stderr, "FAIL: sync fill\n"); return 1; }

        /* a delta whose previous header links to the pinned tip extends it */
        kw_headerstore_append(&s, &h2);
        lens[0] = mk_cfheaders(msgs, h2.hash, chain1, hash2);
        lens[1] = mk_cfilter(msgs + lens[0], h2.hash, f2, sizeof f2);
        if (sync_round(&s, sp, msgs, lens, cmds, 2) != 2) { fprintf(stderr, "FAIL: sync delta\n"); return 1; }

        /* a delta that does not link to the pinned tip is refused */
        kw_headerstore_append(&s, &h3);
        uint8_t wrong[32]; memset(wrong, 0, 32);
        lens[0] = mk_cfheaders(msgs, h3.hash, wrong, hash3);
        lens[1] = mk_cfilter(msgs + lens[0], h3.hash, f3, sizeof f3);
        if (sync_round(&s, sp, msgs, lens, cmds, 2) != -1) { fprintf(stderr, "FAIL: broken chain accepted\n"); return 1; }

        /* a filter that does not hash to its committed value is refused */
        uint8_t f3bad[1] = { 0xde };
        lens[0] = mk_cfheaders(msgs, h3.hash, chain2, hash3);
        lens[1] = mk_cfilter(msgs + lens[0], h3.hash, f3bad, sizeof f3bad);
        if (sync_round(&s, sp, msgs, lens, cmds, 2) != -1) { fprintf(stderr, "FAIL: tampered filter accepted\n"); return 1; }
        if (kw_cfstore_count(sp) != 2) { fprintf(stderr, "FAIL: refused filter cached\n"); return 1; }

        /* Without the sidecar the two cached filters are tied to nothing, so the sync
           refuses rather than re-adopting whatever base the peer now offers. Deleting
           it is the cheapest way to get trust-on-first-use back. */
        snprintf(aux, sizeof aux, "%s.fh", sp);  remove(aux);
        lens[0] = mk_cfheaders(msgs, h3.hash, chain2, hash3);
        lens[1] = mk_cfilter(msgs + lens[0], h3.hash, f3, sizeof f3);
        if (sync_round(&s, sp, msgs, lens, cmds, 2) != -1) {
            fprintf(stderr, "FAIL: a cache with no sidecar was synced anyway\n"); return 1;
        }

        /* A sidecar behind the cache means the tail was never verified: it is dropped
           and re-fetched. The rewritten sidecar is what shows the drop happened, since
           a cache left at two entries would have returned early without asking. */
        if (!fh_poke(sp, 1, chain1)) { fprintf(stderr, "FAIL: cannot write the sidecar\n"); return 1; }
        lens[0] = mk_cfheaders(msgs, h2.hash, chain1, hash2);
        lens[1] = mk_cfilter(msgs + lens[0], h2.hash, f2, sizeof f2);
        {
            kw_headerstore s2; kw_headerstore_init(&s2);
            kw_headerstore_append(&s2, &h1);
            kw_headerstore_append(&s2, &h2);
            long r = sync_round(&s2, sp, msgs, lens, cmds, 2);
            kw_headerstore_free(&s2);
            if (r != 2) { fprintf(stderr, "FAIL: resync after the drop reported %ld\n", r); return 1; }
        }
        long back = 0;
        if (!fh_peek(sp, &back) || back != 2) {
            fprintf(stderr, "FAIL: the unverified tail was kept, sidecar still at %ld\n", back);
            return 1;
        }

        kw_headerstore_free(&s);
        remove(sp);
        snprintf(aux, sizeof aux, "%s.idx", sp); remove(aux);
        snprintf(aux, sizeof aux, "%s.fh", sp);  remove(aux);

        /* A filter-header anchor is checked as the chain is built, so a peer
           serving a consistent chain of its own is caught at the first anchor
           rather than believed. Height 1 is store index 0. */
        char good[65], bad[65];
        uint8_t other[32]; memset(other, 0x5a, 32);
        hex_rev(chain1, good);
        hex_rev(other, bad);

        kw_headerstore s2; kw_headerstore_init(&s2);
        kw_headerstore_append(&s2, &h1);
        lens[0] = mk_cfheaders(msgs, h1.hash, prev0, hash1);
        lens[1] = mk_cfilter(msgs + lens[0], h1.hash, f1, sizeof f1);

        kw_chainparams cpa = KW_DOGE_REGTEST;
        kw_cfcheckpoint anchor[1];
        cpa.cfcheckpoints = anchor; cpa.ncfcheckpoints = 1;

        anchor[0].height = 1; anchor[0].header = good;
        if (sync_round_cp(&cpa, &s2, sp, msgs, lens, cmds, 2) != 1) {
            fprintf(stderr, "FAIL: matching anchor refused\n"); return 1; }
        remove(sp);
        snprintf(aux, sizeof aux, "%s.idx", sp); remove(aux);
        snprintf(aux, sizeof aux, "%s.fh", sp);  remove(aux);

        anchor[0].header = bad;
        if (sync_round_cp(&cpa, &s2, sp, msgs, lens, cmds, 2) != -1) {
            fprintf(stderr, "FAIL: chain contradicting the anchor accepted\n"); return 1; }
        if (kw_cfstore_count(sp) > 0) {
            fprintf(stderr, "FAIL: filter cached despite anchor mismatch\n"); return 1; }

        kw_headerstore_free(&s2);
        remove(sp);
        snprintf(aux, sizeof aux, "%s.idx", sp); remove(aux);
        snprintf(aux, sizeof aux, "%s.fh", sp);  remove(aux);
    }

    printf("cfstore ok: append, count, match hit/miss, height-range skip, corrupt tag rejected, commitment chain pinned, tamper refused,\n  a cache with no sidecar refused and one past it re-fetched, filter-header anchor enforced\n");
    return 0;
}
