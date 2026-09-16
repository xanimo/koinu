/* koinu.dog - header parsing, hashing, and chain store tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Vectors are the first three Dogecoin regtest headers (genesis, 1, 2) taken
 * from dogecoin-cli getblockheader; regtest blocks carry no AuxPoW. */

#include "headers.h"
#include "msg.h"
#include "testutil.h"
#include "hex.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *GENESIS_HDR =
    "010000000000000000000000000000000000000000000000000000000000000000000000"
    "696ad20e2dd4365c7459b4a4a5af743d5e92c6da3229e6532cd605f6533f2a5b"
    "dae5494dffff7f2002000000";
static const char *GENESIS_DISP = "3d2160a3b5dc4a9d62e7e66a295f70313ac808440ef7400d6c0772171ce973a5";
static const char *B1_HDR =
    "04006200a573e91c1772076c0d40f70e4408c83a31705f296ae6e7629d4adcb5a360213d"
    "85711eab5e7932893bc19abe378e66701a242ec323416a743996aa672de18b26"
    "36c59c6affff7f2001000000";
static const char *B1_DISP = "215ae97e66fc7e5d762cc3fe3d92d2b8bbf33b691b4ea9edf2c63d25dcae5ed0";
static const char *B2_HDR =
    "04006200d05eaedc253dc6f2eda94e1b693bf3bbb8d2923dfec32c765d7efc667ee95a21"
    "84daf2f79c0d16ae28cc536e79f2bad55534cca9049fe8359b99c047386cdc65"
    "37c59c6affff7f2000000000";
static const char *B2_DISP = "dc413d41281d45e001b388406f4e5e31dfee12b23544972e0953bb31386cf8b7";

static void disp(const uint8_t h[32], char out[65])
{
    uint8_t r[32];
    for (int i = 0; i < 32; i++) r[i] = h[31 - i];
    kw_hex_encode(r, 32, out, 65);
}

/* Append one AuxPoW header entry (80-byte header + auxpow blob + tx count 0) in
   Core's serialization order. (segwit) marks the parent coinbase segwit. */
static size_t put_auxpow_entry(uint8_t *b, size_t n, const uint8_t hdr[80], int segwit)
{
    memcpy(b + n, hdr, 80); n += 80;
    /* parent coinbase */
    b[n++]=0x01; b[n++]=0; b[n++]=0; b[n++]=0;                 /* tx version */
    if (segwit) { b[n++]=0x00; b[n++]=0x01; }                 /* marker, flag */
    b[n++]=0x01;                                              /* 1 input */
    memset(b + n, 0, 32); n += 32;                            /* prevout hash */
    b[n++]=0xff; b[n++]=0xff; b[n++]=0xff; b[n++]=0xff;       /* prevout index */
    b[n++]=0x03; b[n++]=0xaa; b[n++]=0xbb; b[n++]=0xcc;       /* scriptSig */
    b[n++]=0xff; b[n++]=0xff; b[n++]=0xff; b[n++]=0xff;       /* sequence */
    b[n++]=0x01; memset(b + n, 0, 8); n += 8;                 /* 1 output, value */
    b[n++]=0x01; b[n++]=0x51;                                 /* scriptPubKey OP_1 */
    if (segwit) { b[n++]=0x01; b[n++]=0x20; memset(b + n, 0x77, 32); n += 32; }  /* 1 witness item */
    b[n++]=0; b[n++]=0; b[n++]=0; b[n++]=0;                   /* locktime */
    /* CMerkleTx tail */
    memset(b + n, 0x22, 32); n += 32;                         /* hashBlock */
    b[n++]=0x00;                                              /* vMerkleBranch (0) */
    b[n++]=0; b[n++]=0; b[n++]=0; b[n++]=0;                   /* nIndex */
    b[n++]=0x00;                                              /* vChainMerkleBranch (0) */
    b[n++]=0; b[n++]=0; b[n++]=0; b[n++]=0;                   /* nChainIndex */
    memset(b + n, 0x33, 80); n += 80;                         /* parentBlock */
    b[n++]=0x00;                                              /* tx count */
    return n;
}

int main(void)
{
    uint8_t g[80], b1[80], b2[80];
    if (kw_test_unhex(GENESIS_HDR, g) != 80 || kw_test_unhex(B1_HDR, b1) != 80 ||
        kw_test_unhex(B2_HDR, b2) != 80) { fprintf(stderr, "FAIL: header hex len\n"); return 1; }

    kw_block_header hg, h1, h2;
    kw_block_header_parse(g, 80, &hg);
    kw_block_header_parse(b1, 80, &h1);
    kw_block_header_parse(b2, 80, &h2);

    char d[65];
    disp(hg.hash, d); if (strcmp(d, GENESIS_DISP)) { fprintf(stderr, "FAIL: genesis hash %s\n", d); return 1; }
    disp(h1.hash, d); if (strcmp(d, B1_DISP))      { fprintf(stderr, "FAIL: block1 hash %s\n", d); return 1; }
    disp(h2.hash, d); if (strcmp(d, B2_DISP))      { fprintf(stderr, "FAIL: block2 hash %s\n", d); return 1; }

    /* block1 links to genesis at the header level */
    if (memcmp(kw_block_header_prev(&h1), hg.hash, 32) != 0) { fprintf(stderr, "FAIL: b1 prev\n"); return 1; }

    /* parse a headers message: count=2, header+0x00 tx count, twice */
    uint8_t payload[256]; size_t n = 0;
    payload[n++] = 0x02;
    memcpy(payload + n, b1, 80); n += 80; payload[n++] = 0x00;
    memcpy(payload + n, b2, 80); n += 80; payload[n++] = 0x00;
    kw_block_header got[KW_MAX_HEADERS]; size_t ng = 0;
    if (kw_msg_headers_parse(payload, n, got, KW_MAX_HEADERS, &ng) != 1 || ng != 2) {
        fprintf(stderr, "FAIL: headers parse\n"); return 1;
    }
    disp(got[0].hash, d); if (strcmp(d, B1_DISP)) { fprintf(stderr, "FAIL: parsed b1\n"); return 1; }
    disp(got[1].hash, d); if (strcmp(d, B2_DISP)) { fprintf(stderr, "FAIL: parsed b2\n"); return 1; }

    /* the store accepts a linking chain and rejects a gap */
    kw_headerstore s;
    kw_headerstore_init(&s);
    if (!kw_headerstore_append(&s, &hg) || !kw_headerstore_append(&s, &h1) ||
        !kw_headerstore_append(&s, &h2)) { fprintf(stderr, "FAIL: store append chain\n"); return 1; }
    if (memcmp(kw_headerstore_tip(&s)->hash, h2.hash, 32) != 0) { fprintf(stderr, "FAIL: tip\n"); return 1; }
    kw_headerstore_free(&s);

    kw_headerstore s2;
    kw_headerstore_init(&s2);
    if (!kw_headerstore_append(&s2, &hg)) { fprintf(stderr, "FAIL: seed\n"); return 1; }
    if (kw_headerstore_append(&s2, &h2)) { fprintf(stderr, "FAIL: store accepted a gap\n"); return 1; }
    kw_headerstore_free(&s2);

    /* getheaders body: version, one locator (genesis), zero hash_stop */
    uint8_t (*loc)[32] = (uint8_t (*)[32])hg.hash;
    uint8_t gh[128];
    size_t gn = kw_msg_getheaders_build(KW_PROTOCOL_VERSION, loc, 1, NULL, gh, sizeof gh);
    if (gn != 4 + 1 + 32 + 32) { fprintf(stderr, "FAIL: getheaders len %zu\n", gn); return 1; }
    if (gh[4] != 0x01 || memcmp(gh + 5, hg.hash, 32) != 0) { fprintf(stderr, "FAIL: getheaders body\n"); return 1; }

    /* an auxpow header's merged-mining blob is skipped, so a following header
       still parses. the auxpow header keeps the same 80-byte hash. */
    {
        uint8_t aux[80];
        memset(aux, 0x11, 80);
        aux[0]=0x02; aux[1]=0x01; aux[2]=0x62; aux[3]=0x00;   /* version 0x00620102, auxpow bit set */
        kw_block_header expaux; kw_block_header_parse(aux, 80, &expaux);

        for (int segwit = 0; segwit <= 1; segwit++) {
            uint8_t buf[1024]; size_t bn = 0;
            buf[bn++] = 0x02;                                 /* two headers */
            bn = put_auxpow_entry(buf, bn, aux, segwit);
            const uint8_t *follow = segwit ? b2 : b1;
            memcpy(buf + bn, follow, 80); bn += 80; buf[bn++] = 0x00;

            kw_block_header ah[8]; size_t an = 0;
            if (kw_msg_headers_parse(buf, bn, ah, 8, &an) != 1 || an != 2) {
                fprintf(stderr, "FAIL: auxpow parse (segwit=%d)\n", segwit); return 1;
            }
            if (memcmp(ah[0].hash, expaux.hash, 32) != 0) {
                fprintf(stderr, "FAIL: auxpow header hash (segwit=%d)\n", segwit); return 1;
            }
            const uint8_t *want = segwit ? h2.hash : h1.hash;
            if (memcmp(ah[1].hash, want, 32) != 0) {
                fprintf(stderr, "FAIL: header after auxpow not reached (segwit=%d)\n", segwit); return 1;
            }
        }
    }

    /* the on-disk cache round-trips the chain and rejects a broken link */
    {
        kw_headerstore ss;
        kw_headerstore_init(&ss);
        kw_headerstore_append(&ss, &hg); kw_headerstore_append(&ss, &h1); kw_headerstore_append(&ss, &h2);
        const char *tmp = "test_headers_cache.tmp";
        if (!kw_headerstore_save(&ss, tmp)) { fprintf(stderr, "FAIL: header save\n"); return 1; }
        kw_headerstore_free(&ss);

        kw_headerstore ld;
        kw_headerstore_init(&ld);
        if (!kw_headerstore_load(&ld, tmp)) { fprintf(stderr, "FAIL: header load\n"); return 1; }
        if (ld.count != 3 || memcmp(kw_headerstore_tip(&ld)->hash, h2.hash, 32) != 0) {
            fprintf(stderr, "FAIL: header cache tip\n"); return 1;
        }
        kw_headerstore_free(&ld);

        /* a truncated file (odd trailing bytes) is rejected */
        FILE *f = fopen(tmp, "ab"); if (f) { uint8_t junk[10] = {0}; fwrite(junk, 1, sizeof junk, f); fclose(f); }
        kw_headerstore bad; kw_headerstore_init(&bad);
        if (kw_headerstore_load(&bad, tmp)) { fprintf(stderr, "FAIL: corrupt cache accepted\n"); return 1; }
        kw_headerstore_free(&bad);
        remove(tmp);

        /* a missing file loads as empty without error */
        kw_headerstore none; kw_headerstore_init(&none);
        if (!kw_headerstore_load(&none, "test_headers_nope.tmp") || none.count != 0) {
            fprintf(stderr, "FAIL: missing cache\n"); return 1;
        }
        kw_headerstore_free(&none);

        /* saving a grown store onto its own cache appends rather than rewrites:
           a byte poked past the tag survives a delta save (a rewrite would
           clear it) but tail divergence forces the rewrite */
        kw_headerstore g; kw_headerstore_init(&g);
        kw_headerstore_append(&g, &hg); kw_headerstore_append(&g, &h1);
        if (!kw_headerstore_save(&g, tmp)) { fprintf(stderr, "FAIL: base save\n"); return 1; }
        f = fopen(tmp, "r+b");
        if (!f) { fprintf(stderr, "FAIL: poke open\n"); return 1; }
        fseek(f, 4, SEEK_SET); int orig = fgetc(f);
        fseek(f, 4, SEEK_SET); fputc(orig ^ 1, f);
        fclose(f);
        kw_headerstore_append(&g, &h2);
        if (!kw_headerstore_save(&g, tmp)) { fprintf(stderr, "FAIL: delta save\n"); return 1; }
        f = fopen(tmp, "rb");
        fseek(f, 4, SEEK_SET);
        int now = fgetc(f);
        fclose(f);
        if (now != (orig ^ 1)) { fprintf(stderr, "FAIL: delta save rewrote the prefix\n"); return 1; }
        f = fopen(tmp, "r+b");                        /* diverge the tail record's hash */
        fseek(f, -1, SEEK_END); int t = fgetc(f); fseek(f, -1, SEEK_END); fputc(t ^ 1, f);
        fclose(f);
        if (!kw_headerstore_save(&g, tmp)) { fprintf(stderr, "FAIL: rewrite save\n"); return 1; }
        f = fopen(tmp, "rb");
        fseek(f, 4, SEEK_SET);
        now = fgetc(f);
        fclose(f);
        if (now != orig) { fprintf(stderr, "FAIL: diverged tail did not rewrite\n"); return 1; }
        kw_headerstore ld2; kw_headerstore_init(&ld2);
        if (!kw_headerstore_load(&ld2, tmp) || ld2.count != 3) { fprintf(stderr, "FAIL: reload after saves\n"); return 1; }
        kw_headerstore_free(&ld2);
        kw_headerstore_free(&g);

        /* an old raw-only KWH1 file still loads, rehashing each record */
        f = fopen(tmp, "wb");
        if (!f) { fprintf(stderr, "FAIL: v1 write\n"); return 1; }
        fwrite("KWH1", 1, 4, f);
        fwrite(hg.raw, 1, KW_HEADER_LEN, f);
        fwrite(h1.raw, 1, KW_HEADER_LEN, f);
        fwrite(h2.raw, 1, KW_HEADER_LEN, f);
        fclose(f);
        kw_headerstore v1; kw_headerstore_init(&v1);
        if (!kw_headerstore_load(&v1, tmp) || v1.count != 3 ||
            memcmp(kw_headerstore_tip(&v1)->hash, h2.hash, 32) != 0) {
            fprintf(stderr, "FAIL: v1 cache load\n"); return 1;
        }
        kw_headerstore_free(&v1);
        remove(tmp);
    }

    /* A chain longer than two of the loader's 4096-record chunks, because the load
       reads in chunks and carries a partial record across the boundary. Nothing
       above reaches past one chunk, so the handoff and the trailing-record cases
       were exactly what the chunked rewrite could break without a red test. */
    {
        enum { BIG = 10000, CHUNKREC = 4096 };
        kw_block_header *bh = (kw_block_header *)malloc(BIG * sizeof *bh);
        if (!bh) { fprintf(stderr, "FAIL: out of memory\n"); return 1; }
        uint8_t braw[KW_HEADER_LEN];
        const uint8_t *bprev = hg.hash;
        for (int i = 0; i < BIG; i++) {
            memset(braw, 0, sizeof braw);
            braw[0] = (uint8_t)(i + 1);
            braw[68] = (uint8_t)i;
            braw[69] = (uint8_t)(i >> 8);
            memcpy(braw + 4, bprev, 32);
            kw_block_header_parse(braw, KW_HEADER_LEN, &bh[i]);
            bprev = bh[i].hash;
        }

        kw_headerstore bs;
        kw_headerstore_init(&bs);
        kw_headerstore_append(&bs, &hg);
        for (int i = 0; i < BIG; i++)
            if (!kw_headerstore_append(&bs, &bh[i])) { fprintf(stderr, "FAIL: big append %d\n", i); return 1; }
        const char *bt = "test_headers_big.tmp";
        if (!kw_headerstore_save(&bs, bt)) { fprintf(stderr, "FAIL: big save\n"); return 1; }
        kw_headerstore_free(&bs);

        kw_headerstore bl;
        kw_headerstore_init(&bl);
        if (!kw_headerstore_load(&bl, bt) || bl.count != BIG + 1) {
            fprintf(stderr, "FAIL: %zu records across chunks, want %d\n", bl.count, BIG + 1); return 1;
        }
        for (int i = 0; i < BIG; i++)
            if (memcmp(bl.h[i + 1].hash, bh[i].hash, 32) != 0) {
                fprintf(stderr, "FAIL: record %d came back wrong\n", i); return 1;
            }
        kw_headerstore_free(&bl);

        /* a record cut short at the end, at three lengths: one byte, part of the
           hash, and all but one byte of a record */
        long full = 0;
        {
            FILE *fz = fopen(bt, "rb");
            if (!fz || fseek(fz, 0, SEEK_END) != 0) { fprintf(stderr, "FAIL: size\n"); return 1; }
            full = ftell(fz);
            fclose(fz);
        }
        const int cuts[3] = { 1, 40, KW_HDR_REC - 1 };
        for (int c = 0; c < 3; c++) {
            char cut[64]; snprintf(cut, sizeof cut, "test_headers_cut%d.tmp", c);
            FILE *src = fopen(bt, "rb"), *dst = fopen(cut, "wb");
            if (!src || !dst) { fprintf(stderr, "FAIL: cut open\n"); return 1; }
            for (long k = 0; k < full - cuts[c]; k++) fputc(fgetc(src), dst);
            fclose(src);
            if (fclose(dst) != 0) { fprintf(stderr, "FAIL: cut write\n"); return 1; }

            kw_headerstore cs;
            kw_headerstore_init(&cs);
            if (kw_headerstore_load(&cs, cut)) {
                fprintf(stderr, "FAIL: a file %d bytes short loaded\n", cuts[c]); return 1;
            }
            kw_headerstore_free(&cs);
            remove(cut);
        }

        /* and a link broken in the middle, then broken exactly on the chunk
           boundary, which is the record the buffer handoff straddles */
        const int breaks[2] = { 5000, CHUNKREC };
        for (int b = 0; b < 2; b++) {
            char brk[64]; snprintf(brk, sizeof brk, "test_headers_brk%d.tmp", b);
            FILE *src = fopen(bt, "rb"), *dst = fopen(brk, "wb");
            if (!src || !dst) { fprintf(stderr, "FAIL: break open\n"); return 1; }
            for (long k = 0; k < full; k++) {
                int ch = fgetc(src);
                /* one byte of that record's prev field */
                if (k == 4 + (long)breaks[b] * KW_HDR_REC + 5) ch ^= 1;
                fputc(ch, dst);
            }
            fclose(src);
            if (fclose(dst) != 0) { fprintf(stderr, "FAIL: break write\n"); return 1; }

            kw_headerstore bs2;
            kw_headerstore_init(&bs2);
            if (kw_headerstore_load(&bs2, brk)) {
                fprintf(stderr, "FAIL: a link broken at record %d loaded\n", breaks[b]); return 1;
            }
            if (bs2.count != (size_t)breaks[b]) {
                fprintf(stderr, "FAIL: stopped at %zu, want %d\n", bs2.count, breaks[b]); return 1;
            }
            kw_headerstore_free(&bs2);
            remove(brk);
        }

        remove(bt);
        free(bh);
    }

    printf("headers ok: hashes, parse, auxpow skip, store links, getheaders, disk cache v1+v2,\n"
           "  delta save, and 10000 records over three chunks with a cut record and a link\n"
           "  broken on the chunk boundary refused\n");
    return 0;
}
