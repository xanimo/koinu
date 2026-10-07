/* koinu.dog - fuzz harnesses for the parsers that read untrusted bytes
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Every one of these consumes input this process did not write: a p2p frame, a
 * transaction or block off the wire, a compact filter, a psbt from a counterparty,
 * and the files a previous run left behind. Each target must not crash, read out of
 * bounds, or leak, whatever the bytes say; returning "malformed" is always a valid
 * answer.
 *
 * The file parsers belong here as much as the wire ones. What is in those files came
 * off the wire to begin with, nothing but this program and whoever can write the
 * directory edits them, and a wallet reads them with the seed in memory. An unbounded
 * %s in the utxo loader lived a long time because only the wire parsers were covered.
 *
 * Built with libFuzzer (make fuzz), or standalone (make fuzz-run) where main()
 * below feeds it files, so a corpus can be replayed without clang. The two
 * targets that need a connection or the daemon's own source are in
 * fuzz/fuzz_wire.c, which is libFuzzer only. */

#include "psbt.h"
#include "tx.h"
#include "sha2.h"
#include "msg.h"
#include "proto.h"
#include "spv.h"
#include "gcs.h"
#include "headers.h"
#include "cf.h"
#include "utxo.h"
#include "journal.h"
#include "cfstore.h"
#include "keystore.h"
#include "peer.h"
#include "ec.h"

#include <unistd.h>

#include <stdint.h>
#include <stdio.h>
#include "auxpow.h"

#include <stdlib.h>
#include <string.h>

/* Recompute a block's merkle root over the body as it stands, and report the
   txid at (want). A mutated body otherwise fails the root check before any of
   the walking code runs. Returns 1 when the root was patched. */
static int fuzz_patch_root(uint8_t *msg, size_t len, uint8_t txid_out[32], unsigned want)
{
    if (len < KW_HEADER_LEN + 1) return 0;
    uint32_t version = (uint32_t)msg[0] | (uint32_t)msg[1] << 8 |
                       (uint32_t)msg[2] << 16 | (uint32_t)msg[3] << 24;
    size_t off = KW_HEADER_LEN;
    if ((version & KW_BLOCK_VERSION_AUXPOW) && !kw_auxpow_skip(msg, len, &off)) return 0;
    if (off >= len) return 0;

    uint8_t pfx = msg[off++];
    uint64_t ntx = pfx;
    if (pfx >= 0xfd) {
        int k = pfx == 0xfd ? 2 : pfx == 0xfe ? 4 : 8;
        if (off + (size_t)k > len) return 0;
        ntx = 0;
        for (int i = 0; i < k; i++) ntx |= (uint64_t)msg[off + i] << (8 * i);
        off += (size_t)k;
    }
    if (ntx == 0 || ntx > 4096) return 0;

    uint8_t (*h)[32] = (uint8_t (*)[32])malloc((size_t)ntx * 32);
    if (!h) return 0;
    size_t n = 0;
    for (uint64_t i = 0; i < ntx; i++) {
        uint8_t txid[32];
        size_t c = kw_tx_scan(msg + off, len - off, txid, NULL, NULL, NULL);
        if (!c) { free(h); return 0; }
        kw_hash256(msg + off, c, h[n]);
        if (i == want) memcpy(txid_out, txid, 32);
        n++; off += c;
    }
    while (n > 1) {
        size_t w = 0;
        for (size_t i = 0; i < n; i += 2, w++) {
            uint8_t cat[64];
            memcpy(cat, h[i], 32);
            memcpy(cat + 32, (i + 1 < n) ? h[i + 1] : h[i], 32);
            kw_hash256(cat, 64, h[w]);
        }
        n = w;
    }
    memcpy(msg + 36, h[0], 32);
    free(h);
    return 1;
}

/* Write (n) bytes to (path), for the parsers that take a filename. */
static int fuzz_spill(const char *path, const uint8_t *b, size_t n)
{
    FILE *f = fopen(path, "wb");
    if (!f) return 0;
    if (n) fwrite(b, 1, n, f);
    return fclose(f) == 0;
}

/* One byte of the input picks the target, so a single corpus covers them all
   and the fuzzer learns to reach each. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) return 0;
    uint8_t which = data[0];
    const uint8_t *in = data + 1;
    size_t len = size - 1;

    switch (which % 16) {
    case 0: {                                  /* a transaction off the wire */
        kw_tx tx;
        if (kw_tx_parse(in, len, &tx) > 0) {
            uint8_t out[16384];
            kw_tx_serialize(&tx, out, sizeof out);
        }
        break;
    }
    case 1: {                                  /* a counterparty's psbt */
        kw_psbt p;
        if (kw_psbt_parse(in, len, &p)) {
            uint8_t out[32768];
            kw_psbt_serialize(&p, out, sizeof out);
            uint8_t pk[33], sig[80]; size_t sl = sizeof sig;
            kw_psbt_get_sig(&p, 0, 0, pk, sig, &sl);
        }
        kw_psbt_free(&p);
        break;
    }
    case 2: {                                  /* a p2p frame */
        char cmd[13]; const uint8_t *pl = NULL; size_t pn = 0;
        kw_msg_parse(0xc0c0c0c0, in, len, cmd, &pl, &pn);
        break;
    }
    case 3: {                                  /* a headers message */
        kw_block_header *hs = (kw_block_header *)malloc(KW_MAX_HEADERS * sizeof *hs);
        if (hs) {
            size_t nout = 0;
            kw_msg_headers_parse(in, len, hs, KW_MAX_HEADERS, &nout);
            free(hs);
        }
        break;
    }
    case 4: {                                  /* a block, scanned for our scripts */
        kw_utxoset us; kw_watchset ws;
        kw_utxoset_init(&us); kw_watchset_init(&ws);
        uint8_t spk[25] = { 0x76, 0xa9, 0x14 };
        memset(spk + 3, 0x42, 20); spk[23] = 0x88; spk[24] = 0xac;
        kw_watchset_add(&ws, spk, sizeof spk);
        kw_block_scan(in, len, &us, &ws, 1);
        kw_watchset_free(&ws); kw_utxoset_free(&us);
        break;
    }
    case 5: {                                  /* a compact filter and its message */
        if (len > 32) {
            kw_gcs_item it = { in, 8 };
            kw_gcs_match_any(in + 32, len - 32, in, &it, 1);
        }
        uint8_t type, bh[32]; const uint8_t *f; size_t fl;
        kw_msg_cfilter_parse(in, len, &type, bh, &f, &fl);
        uint8_t stop[32], prev[32]; const uint8_t *hh; size_t nh;
        kw_msg_cfheaders_parse(in, len, &type, stop, prev, &hh, &nh);
        break;
    }
    case 10: {                                 /* the merged-mining structure check */
        /* kw_auxpow_parse is reached through cases 3 and 4, but the structure
           check behind it was reached by nothing except the four real proofs in
           the test vector, and it is the code that decides whether a header
           proves its work. Takes 32 bytes as the block hash the proof should
           commit to, the rest as the blob.

           The corpus entry for this has to be a real proof. Seeded from noise the
           parser rejects everything and the check never runs at all: 200000
           iterations reached it zero times, against 1396600 when mutating a
           genuine one. */
        if (len < 33) break;
        uint8_t aux_hash[32];
        memcpy(aux_hash, in, 32);
        size_t off = 0;
        kw_auxpow ap;
        if (kw_auxpow_parse(in + 32, len - 32, &off, &ap))
            (void)kw_auxpow_check_structure(&ap, aux_hash, KW_AUXPOW_CHAIN_ID);
        break;
    }
    case 6:                                    /* the tracked utxo set */
    case 7:                                    /* the wallet journal */
    case 8:                                    /* a header cache */
    case 9: {                                  /* the compact filter store */
        /* These take a path rather than a buffer, so the bytes go through a file.
           One name per process, removed after, so a long run does not fill the disk. */
        char path[64];
        snprintf(path, sizeof path, "/tmp/kwfuzz-%d", (int)getpid());
        FILE *f = fopen(path, "wb");
        if (!f) break;
        if (len) fwrite(in, 1, len, f);
        fclose(f);

        if (which % 16 == 6) {
            kw_utxoset us;
            if (kw_utxoset_init(&us)) { kw_utxoset_load(&us, path); kw_utxoset_free(&us); }
        } else if (which % 16 == 7) {
            kw_journal j;
            if (kw_journal_init(&j)) { kw_journal_load(&j, path); kw_journal_free(&j); }
        } else if (which % 16 == 8) {
            kw_headerstore hs;
            if (kw_headerstore_init(&hs)) { kw_headerstore_load(&hs, path); kw_headerstore_free(&hs); }
        } else {
            kw_cfstore_count(path);            /* walks every record's varint length */
        }
        unlink(path);
        break;
    }
    case 11: {                                 /* a peer's version payload */
        /* The first thing any peer sends, parsed before the handshake decides
           anything, and the one wire parser the dispatch above never reached.
           A successful parse is rebuilt and reparsed: the fixed fields have to
           survive, and the user agent has to stay inside the buffer it was
           given, whatever the wire said its length was. */
        if (len < 1) break;
        size_t uacap = in[0] ? in[0] : 256;
        char *ua = (char *)malloc(uacap);
        if (!ua) break;
        kw_msg_version v;
        if (kw_msg_version_parse(in + 1, len - 1, &v, ua, uacap)) {
            if (strlen(v.user_agent) >= uacap) abort();
            uint8_t out[2048];
            size_t n = kw_msg_version_build(&v, out, sizeof out);
            kw_msg_version v2; char ua2[256];
            if (n && kw_msg_version_parse(out, n, &v2, ua2, sizeof ua2) &&
                (v2.version != v.version || v2.nonce != v.nonce ||
                 v2.start_height != v.start_height)) abort();
        }
        free(ua);
        break;
    }
    case 12: {                                 /* a block, merkle gate and outpoint */
        /* Case 4 scans a block; this one goes at the two functions a merchant's
           answer depends on. The root is recomputed over whatever body the
           mutation produced when the mode byte asks, because a peer can always
           do that much: what it cannot do is the header's work, which is not
           what these two check. Without the patch the merkle gate refuses
           almost every mutation and find_outpoint is never reached. */
        if (len < 6) break;
        uint8_t mode = in[0];
        uint32_t vout = (uint32_t)in[1] | (uint32_t)in[2] << 8 |
                        (uint32_t)in[3] << 16 | (uint32_t)in[4] << 24;
        size_t blen = len - 5;
        uint8_t *msg = (uint8_t *)malloc(blen ? blen : 1);
        if (!msg) break;
        memcpy(msg, in + 5, blen);
        uint8_t txid[32];
        memset(txid, 0x11, 32);
        if (mode & 1) fuzz_patch_root(msg, blen, txid, (mode >> 1) & 15);
        uint8_t spk[25] = { 0x76, 0xa9, 0x14 };
        memset(spk + 3, 0x42, 20); spk[23] = 0x88; spk[24] = 0xac;
        (void)kw_block_merkle_ok(msg, blen);
        kw_outpoint_status st;
        memset(&st, 0, sizeof st);
        (void)kw_block_find_outpoint(msg, blen, txid, vout, spk, sizeof spk, &st);
        free(msg);
        break;
    }
    case 13: {                                 /* a filter, decoded and matched */
        /* match_any walks the golomb-rice stream without building the set;
           decode builds it. Where both answer, they have to agree, which is a
           property no crash-only run of case 5 can check. */
        if (len < 34) break;
        const uint8_t *bh = in;
        size_t nitems = in[32] % 9;
        kw_gcs_item items[8];
        size_t off = 33;
        size_t k = 0;
        for (; k < nitems && off < len; k++) {
            size_t want = in[off++] % 48;
            if (want > len - off) want = len - off;
            items[k].script = in + off;
            items[k].len = want;
            off += want;
        }
        const uint8_t *filt = in + off;
        size_t flen = len - off;
        int m = kw_gcs_match_any(filt, flen, bh, items, k);

        size_t cap = flen * 8 + 1;
        if (cap > (1u << 16)) cap = 1u << 16;
        uint64_t *vals = (uint64_t *)malloc(cap * sizeof *vals);
        if (!vals) break;
        long nn = kw_gcs_decode(filt, flen, vals, cap);
        if (m >= 0 && nn >= 0) {
            int want = 0;
            for (size_t i = 0; i < k && !want; i++) {
                if (!items[i].len) continue;
                uint64_t t = kw_gcs_hash(bh, (uint64_t)nn, items[i].script, items[i].len);
                for (long j = 0; j < nn; j++) if (vals[j] == t) { want = 1; break; }
            }
            if (want != m) abort();
        }
        free(vals);
        break;
    }
    case 14: {                                 /* the filter cache and its sidecars */
        /* Case 9 counts the records; this one tests scripts against a range,
           which is the path kwd answers from, and writes the .idx and .fh
           sidecars the range walk seeks through. */
        if (len < 4) break;
        uint8_t mode = in[0];
        uint32_t from = in[1];
        size_t nh = in[2] % 8;
        const uint8_t *rest = in + 3;
        size_t rlen = len - 3;

        char path[64], aux[80];
        snprintf(path, sizeof path, "/tmp/kwfuzz-cf-%d", (int)getpid());
        size_t half = rlen / 2;
        if (!fuzz_spill(path, rest, half)) break;
        if (mode & 1) {
            snprintf(aux, sizeof aux, "%s.idx", path);
            fuzz_spill(aux, rest + half, rlen - half);
        }
        if (mode & 2) {
            snprintf(aux, sizeof aux, "%s.fh", path);
            fuzz_spill(aux, rest + half, rlen - half);
        }

        kw_headerstore hs;
        if (kw_headerstore_init(&hs)) {
            uint8_t raw[80];
            uint8_t prev[32];
            memset(prev, 0, sizeof prev);
            for (size_t i = 0; i < nh; i++) {
                memset(raw, 0, sizeof raw);
                raw[0] = 1;
                if (i) memcpy(raw + 4, prev, 32);
                raw[36] = (uint8_t)(i + 1);
                kw_block_header h;
                if (!kw_block_header_parse(raw, 80, &h)) break;
                if (!kw_headerstore_append(&hs, &h)) break;
                memcpy(prev, h.hash, 32);
            }
            uint8_t spk[25] = { 0x76, 0xa9, 0x14 };
            memset(spk + 3, 0x42, 20); spk[23] = 0x88; spk[24] = 0xac;
            kw_gcs_item it = { spk, sizeof spk };
            uint32_t heights[8];
            kw_cfstore_match_range(path, (mode & 4) ? &hs : NULL, 1, from,
                                   &it, 1, heights, 8);
            kw_headerstore_free(&hs);
        }
        unlink(path);
        snprintf(aux, sizeof aux, "%s.idx", path); unlink(aux);
        snprintf(aux, sizeof aux, "%s.fh", path);  unlink(aux);
        break;
    }
    case 15: {                                 /* a keystore file */
        /* The 52-byte header is the AEAD's associated data, so it is not altered
           here. argon2 runs before the tag can fail, and the library accepts up
           to t=8 and 1 GiB, so a legal-but-expensive header would cost seconds
           and a gigabyte an exec: those are skipped, and everything outside the
           library's range still goes in so its own refusal is exercised. */
        if (len >= 8192) break;                /* read_keystore refuses it */
        if (len >= 20) {
            uint32_t t = (uint32_t)in[8]  | (uint32_t)in[9] << 8  |
                         (uint32_t)in[10] << 16 | (uint32_t)in[11] << 24;
            uint32_t m = (uint32_t)in[12] | (uint32_t)in[13] << 8 |
                         (uint32_t)in[14] << 16 | (uint32_t)in[15] << 24;
            uint32_t p = (uint32_t)in[16] | (uint32_t)in[17] << 8 |
                         (uint32_t)in[18] << 16 | (uint32_t)in[19] << 24;
            int legal = t && m && p && t <= KW_KEYSTORE_MAX_T_COST &&
                        m <= KW_KEYSTORE_MAX_M_COST_KIB && p <= KW_KEYSTORE_MAX_PARALLELISM;
            if (legal && (t > 2 || m > 256)) break;
        }
        uint8_t seed[64]; size_t slen = 0;
        if (kw_keystore_open(in, len, "fuzz", seed, sizeof seed, &slen) &&
            (slen == 0 || slen > sizeof seed)) abort();
        break;
    }
    }
    return 0;
}

#ifdef KW_FUZZ_STANDALONE
/* A driver for toolchains without libFuzzer. Every file argument is replayed
   as-is, then each is mutated repeatedly and replayed again. The mutations
   come from a fixed seed, so a crash found here reproduces exactly: the
   iteration number names the input. Build it under the sanitizers (make
   fuzz-run) or the memory errors go unnoticed. */

static uint64_t rng_state = 0x243f6a8885a308d3ULL;
static uint64_t rnd(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

#define MAXIN (1 << 16)

static void mutate(const uint8_t *src, size_t srclen, uint8_t *dst, size_t *dstlen)
{
    size_t n = srclen;
    if (n > MAXIN) n = MAXIN;
    memcpy(dst, src, n);

    int rounds = 1 + (int)(rnd() % 8);
    for (int r = 0; r < rounds && n; r++) {
        switch (rnd() % 4) {
        case 0: dst[rnd() % n] = (uint8_t)rnd(); break;            /* flip a byte */
        case 1: dst[rnd() % n] ^= (uint8_t)(1u << (rnd() % 8)); break;  /* a bit */
        case 2: n = 1 + (size_t)(rnd() % n); break;                /* truncate */
        case 3: {                                                   /* splice */
            size_t a = rnd() % n, b = rnd() % n;
            dst[a] = dst[b];
            break;
        }
        }
    }
    *dstlen = n;
}

int main(int argc, char **argv)
{
    long iters = 20000;
    const char *env = getenv("KW_FUZZ_ITERS");
    if (env) iters = atol(env);

    kw_ec_start();

    static uint8_t seeds[64][MAXIN];
    static size_t seedlen[64];
    int nseed = 0;
    for (int i = 1; i < argc && nseed < 64; i++) {
        FILE *f = fopen(argv[i], "rb");
        if (!f) continue;
        seedlen[nseed] = fread(seeds[nseed], 1, MAXIN, f);
        fclose(f);
        if (seedlen[nseed]) {
            LLVMFuzzerTestOneInput(seeds[nseed], seedlen[nseed]);   /* replay as-is */
            nseed++;
        }
    }
    if (!nseed) {                       /* no corpus: start from noise */
        for (int i = 0; i < 8; i++) {
            seedlen[i] = 64;
            for (size_t k = 0; k < 64; k++) seeds[i][k] = (uint8_t)rnd();
        }
        nseed = 8;
    }

    static uint8_t buf[MAXIN];
    for (long i = 0; i < iters; i++) {
        size_t n = 0;
        mutate(seeds[i % nseed], seedlen[i % nseed], buf, &n);
        LLVMFuzzerTestOneInput(buf, n);
    }

    kw_ec_stop();
    printf("fuzz ok: %d seed(s) replayed, %ld mutations, no crash\n", nseed, iters);
    return 0;
}
#endif
