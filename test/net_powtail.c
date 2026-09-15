/* koinu.dog - what the validator pool sees, one header at a time
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Build on demand. Syncs headers from (height) over one peer and runs, inline,
 * exactly what net/powq.c runs on each: the AuxPoW parse and structure check when
 * the version says merged-mined, then scrypt over whichever header carries the
 * work, then the target check. Prints a line per failure and a tally.
 *
 * It exists because three separate peers were all reported as serving a header
 * that does not prove its work, which is not three bad peers. */

#include "auxpow.h"
#include "chainparams.h"
#include "headers.h"
#include "hex.h"
#include "msg.h"
#include "peer.h"
#include "pow.h"
#include "scrypt.h"
#include "sha2.h"
#include "sync.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void sha256d(const uint8_t *in, size_t len, uint8_t out[32])
{
    uint8_t once[32];
    kw_sha256(in, len, once);
    kw_sha256(once, 32, out);
}

struct seen {
    uint32_t height;
    long checked, aux_n, plain_n, bad_parse, bad_struct, bad_pow;
    long segwit_cb, segwit_bad;
    int dump, dumped;
    uint32_t first_bad;
    int stop;
};

static int on_header(void *ctx, const kw_block_header *h, const uint8_t *aux, size_t auxlen)
{
    struct seen *s = (struct seen *)ctx;
    uint32_t at = s->height++;
    uint32_t version = kw_block_header_version(h);
    uint32_t bits = kw_header_bits(h->raw);

    uint8_t work_hdr[80];
    if (aux && auxlen) {
        s->aux_n++;
        uint8_t id[32];
        sha256d(h->raw, 80, id);
        kw_auxpow ap;
        size_t off = 0;
        if (!kw_auxpow_parse(aux, auxlen, &off, &ap)) {
            if (!s->bad_parse++) printf("%u: auxpow does not parse (version %08x, %zu bytes)\n",
                                        at, version, auxlen);
            if (!s->first_bad) s->first_bad = at;
            return 1;
        }
        int sw = ap.coinbase_len > 6 && ap.coinbase[4] == 0x00 && ap.coinbase[5] == 0x01;
        if (sw) s->segwit_cb++;
        if (sw && s->dump && !s->dumped) {          /* one, as a regression vector */
            s->dumped = 1;
            printf("VECTOR height %u\nheader ", at);
            for (int i = 0; i < 80; i++) printf("%02x", h->raw[i]);
            printf("\naux ");
            for (size_t i = 0; i < auxlen; i++) printf("%02x", aux[i]);
            printf("\n");
        }
        if (!kw_auxpow_check_structure(&ap, id, KW_AUXPOW_CHAIN_ID)) {
            if (sw) s->segwit_bad++;
            if (!s->bad_struct++) printf("%u: auxpow structure refused (version %08x)\n", at, version);
            if (!s->first_bad) s->first_bad = at;
            return 1;
        }
        memcpy(work_hdr, ap.parent, 80);
    } else {
        s->plain_n++;
        memcpy(work_hdr, h->raw, 80);
    }

    uint8_t pow[32];
    if (!kw_scrypt_pow(work_hdr, pow, NULL)) { printf("%u: scrypt failed\n", at); return 0; }
    s->checked++;
    if (!kw_pow_check(pow, bits)) {
        if (!s->bad_pow++)
            printf("%u: hash is not under its target. version %08x, bits %08x, aux %s\n",
                   at, version, bits, (aux && auxlen) ? "yes" : "no");
        if (!s->first_bad) s->first_bad = at;
    }
    return 1;
}

int main(int argc, char **argv)
{
    const char *node = NULL, *cache = NULL;
    uint32_t rounds = 1;
    int dump = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--node") && i + 1 < argc) node = argv[++i];
        else if (!strcmp(argv[i], "--headers") && i + 1 < argc) cache = argv[++i];
        else if (!strcmp(argv[i], "--rounds") && i + 1 < argc) rounds = (uint32_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--dump")) dump = 1;
    }
    if (!node || !cache) {
        fprintf(stderr, "usage: net_powtail --node HOST --headers CACHE [--rounds N]\n");
        return 2;
    }

    const kw_chainparams *cp = &KW_DOGE_MAINNET;
    kw_headerstore s;
    kw_headerstore_init(&s);
    if (!kw_headerstore_load(&s, cache)) { fprintf(stderr, "cache will not load\n"); return 1; }
    printf("cache holds %zu headers\n", s.count);

    kw_peer p;
    if (!kw_peer_connect(&p, cp, node, cp->p2p_port, 15)) { fprintf(stderr, "connect failed\n"); return 1; }
    if (!kw_peer_handshake(&p, 0)) { fprintf(stderr, "handshake failed\n"); return 1; }

    struct seen st;
    memset(&st, 0, sizeof st);
    st.height = (uint32_t)s.count + 1;
    st.dump = dump;

    kw_block_header *batch = (kw_block_header *)malloc(KW_MAX_HEADERS * sizeof *batch);
    if (!batch) return 1;

    uint8_t loc[32];
    memcpy(loc, kw_headerstore_tip(&s)->hash, 32);

    for (uint32_t r = 0; r < rounds; r++) {
        uint8_t body[128];
        size_t bn = kw_msg_getheaders_build(KW_PROTOCOL_VERSION, (const uint8_t (*)[32])loc, 1,
                                            NULL, body, sizeof body);
        if (!bn || !kw_peer_send(&p, "getheaders", body, bn)) { fprintf(stderr, "send failed\n"); break; }

        char cmd[13]; const uint8_t *pl = NULL; size_t pn = 0;
        int got = 0;
        while (kw_peer_recv(&p, cmd, &pl, &pn) == 1) {
            if (!strcmp(cmd, "headers")) { got = 1; break; }
            if (!strcmp(cmd, "ping")) kw_peer_send(&p, "pong", pl, pn);
        }
        if (!got) { fprintf(stderr, "no headers came back\n"); break; }

        size_t nout = 0;
        if (kw_msg_headers_parse_cb(pl, pn, batch, KW_MAX_HEADERS, &nout, on_header, &st) != 1) {
            fprintf(stderr, "headers did not parse\n"); break;
        }
        if (!nout) break;
        memcpy(loc, batch[nout - 1].hash, 32);
    }

    printf("checked %ld: %ld merged-mined, %ld plain. "
           "bad parse %ld, bad structure %ld, bad pow %ld, first bad %u\n",
           st.checked, st.aux_n, st.plain_n, st.bad_parse, st.bad_struct, st.bad_pow, st.first_bad);
    printf("segwit parent coinbases %ld, of which refused %ld\n", st.segwit_cb, st.segwit_bad);
    kw_peer_close(&p);
    kw_headerstore_free(&s);
    free(batch);
    return st.bad_pow || st.bad_parse || st.bad_struct;
}
