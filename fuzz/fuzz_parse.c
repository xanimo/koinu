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
 * below feeds it files, so a corpus can be replayed without clang. */

#include "psbt.h"
#include "tx.h"
#include "msg.h"
#include "proto.h"
#include "spv.h"
#include "gcs.h"
#include "headers.h"
#include "cf.h"
#include "utxo.h"
#include "journal.h"
#include "cfstore.h"
#include "ec.h"

#include <unistd.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* One byte of the input picks the target, so a single corpus covers them all
   and the fuzzer learns to reach each. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) return 0;
    uint8_t which = data[0];
    const uint8_t *in = data + 1;
    size_t len = size - 1;

    switch (which % 10) {
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

        if (which % 10 == 6) {
            kw_utxoset us;
            if (kw_utxoset_init(&us)) { kw_utxoset_load(&us, path); kw_utxoset_free(&us); }
        } else if (which % 10 == 7) {
            kw_journal j;
            if (kw_journal_init(&j)) { kw_journal_load(&j, path); kw_journal_free(&j); }
        } else if (which % 10 == 8) {
            kw_headerstore hs;
            if (kw_headerstore_init(&hs)) { kw_headerstore_load(&hs, path); kw_headerstore_free(&hs); }
        } else {
            kw_cfstore_count(path);            /* walks every record's varint length */
        }
        unlink(path);
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
