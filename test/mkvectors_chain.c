/* koinu.dog - sighash vectors read off the chain
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Built on demand. Fetches a run of mainnet blocks from a peer and writes out, for
 * every spend it can fully account for, the prevout's scriptPubKey, the input index,
 * and the spending transaction. test/test_sighash.c then recomputes the digest and
 * checks the signatures the network already accepted verify against it.
 *
 * The one thing that makes such a vector evidence rather than a restatement is where
 * the scriptPubKey comes from. It is read off the chain: every output in the run is
 * indexed by txid as the blocks are walked, and a spend is only emitted once its
 * prevout is found in that index. Rebuilding the script from the pubkey in the
 * scriptSig would be easy for P2PKH and worthless, since the generator would then be
 * deciding what the digest covers and the vector would only prove this tree agrees
 * with itself.
 *
 * A contiguous run is what makes the index work, and it is why this fetches by height
 * rather than sampling: an output has to be in the run before the input that spends
 * it. Recent heights are used because P2SH does not appear in early Dogecoin at all,
 * 14545 pre-AuxPoW blocks with not one, so the shapes worth having are all late.
 *
 * Nothing here computes a digest or verifies a signature. If it did, it could only
 * emit vectors this tree already passes.
 *
 *   make mkvectors_chain
 *   ./mkvectors_chain --node HOST --headers main.kwh --from 6300000 --count 400
 */

#include "auxpow.h"
#include "chainparams.h"
#include "ec.h"
#include "headers.h"
#include "hex.h"
#include "peer.h"
#include "spv.h"
#include "tx.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── the output index ─────────────────────────────────────────────────────
   txid to that transaction's outputs, for the run being walked. Open addressing on
   the first eight bytes of the txid, which is a hash already. */
#define IDX_BITS 18
#define IDX_SIZE (1u << IDX_BITS)

typedef struct {
    uint8_t  txid[32];
    uint8_t  used;
    size_t   nout;
    uint8_t  spk[8][KW_TX_SCRIPT_MAX];
    size_t   spklen[8];
} idx_entry;

static idx_entry *g_idx;

static size_t idx_slot(const uint8_t txid[32])
{
    uint64_t k = 0;
    memcpy(&k, txid, 8);
    return (size_t)(k & (IDX_SIZE - 1));
}

static void idx_put(const uint8_t txid[32], const kw_tx *tx)
{
    size_t at = idx_slot(txid);
    for (size_t i = 0; i < IDX_SIZE; i++) {
        idx_entry *e = &g_idx[(at + i) & (IDX_SIZE - 1)];
        if (e->used && memcmp(e->txid, txid, 32) == 0) return;
        if (!e->used) {
            memcpy(e->txid, txid, 32);
            e->used = 1;
            e->nout = tx->nout < 8 ? tx->nout : 8;     /* later outputs are rarely spent soon */
            for (size_t o = 0; o < e->nout; o++) {
                e->spklen[o] = tx->vout[o].scriptlen;
                memcpy(e->spk[o], tx->vout[o].script, tx->vout[o].scriptlen);
            }
            return;
        }
    }
}

static const uint8_t *idx_get(const uint8_t txid[32], uint32_t vout, size_t *len)
{
    size_t at = idx_slot(txid);
    for (size_t i = 0; i < IDX_SIZE; i++) {
        idx_entry *e = &g_idx[(at + i) & (IDX_SIZE - 1)];
        if (!e->used) return NULL;
        if (memcmp(e->txid, txid, 32) == 0) {
            if (vout >= e->nout) return NULL;
            *len = e->spklen[vout];
            return e->spk[vout];
        }
    }
    return NULL;
}

/* ── script reading ─────────────────────────────────────────────────────── */

/* Collect the data pushes of a scriptSig. Anything that is not a push makes the
   input one this does not understand, and it is dropped rather than guessed at. */
static int pushes(const uint8_t *s, size_t len, const uint8_t **at, size_t *sz, int max, int *n)
{
    size_t o = 0;
    *n = 0;
    while (o < len) {
        uint8_t op = s[o++];
        size_t l;
        if (op == 0) l = 0;                       /* OP_0, the multisig dummy */
        else if (op <= 75) l = op;
        else if (op == 0x4c) { if (o >= len) return 0; l = s[o++]; }
        else if (op == 0x4d) { if (o + 1 >= len) return 0; l = (size_t)s[o] | ((size_t)s[o+1] << 8); o += 2; }
        else return 0;                            /* an opcode, not a push */
        if (o + l > len) return 0;
        if (*n >= max) return 0;
        at[*n] = s + o;
        sz[*n] = l;
        (*n)++;
        o += l;
    }
    return 1;
}

/* Strict DER, low-S, and SIGHASH_ALL, which is what kw_ec_verify will accept and
   what kw_tx_sighash computes. Mainnet predates BIP66, so plenty of old signatures
   are neither, and shipping those as expected failures teaches a reader to ignore
   failures. */
static int usable_sig(const uint8_t *s, size_t len)
{
    /* the half order of secp256k1: S above this is the other valid signature */
    static const uint8_t HALF_N[32] = {
        0x7f,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0x5d,0x57,0x6e,0x73,0x57,0xa4,0x50,0x1d,0xdf,0xe9,0x2f,0x46,0x68,0x1b,0x20,0xa0
    };
    if (len < 9 || len > 73) return 0;
    if (s[len - 1] != 0x01) return 0;             /* SIGHASH_ALL only */
    size_t dl = len - 1;
    if (s[0] != 0x30 || s[1] != dl - 2) return 0;
    if (s[2] != 0x02) return 0;
    size_t rl = s[3];
    if (rl == 0 || 5 + rl >= dl) return 0;
    if (s[4] & 0x80) return 0;
    if (rl > 1 && s[4] == 0 && !(s[5] & 0x80)) return 0;
    if (s[4 + rl] != 0x02) return 0;
    size_t sl = s[5 + rl];
    if (sl == 0 || 6 + rl + sl != dl) return 0;   /* 30 len 02 rl R 02 sl S */
    const uint8_t *S = s + 6 + rl;
    if (S[0] & 0x80) return 0;
    if (sl > 1 && S[0] == 0 && !(S[1] & 0x80)) return 0;

    uint8_t be[32];
    if (sl > 33) return 0;
    memset(be, 0, sizeof be);
    size_t skip = (sl == 33) ? 1 : 0;             /* a leading zero for the sign bit */
    if (sl - skip > 32) return 0;
    memcpy(be + 32 - (sl - skip), S + skip, sl - skip);
    return memcmp(be, HALF_N, 32) <= 0;
}

static int has_codeseparator(const uint8_t *s, size_t len)
{
    for (size_t i = 0; i < len; i++) if (s[i] == 0xab) return 1;
    return 0;
}

static int contains(const uint8_t *hay, size_t hl, const uint8_t *ndl, size_t nl)
{
    if (nl == 0 || hl < nl) return 0;
    for (size_t i = 0; i + nl <= hl; i++) if (memcmp(hay + i, ndl, nl) == 0) return 1;
    return 0;
}

int main(int argc, char **argv)
{
    const char *node = NULL, *cache = NULL;
    int port = -1;
    unsigned long from = 0, count = 200, want = 200;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--node") && i + 1 < argc) node = argv[++i];
        else if (!strcmp(argv[i], "--port") && i + 1 < argc) port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--headers") && i + 1 < argc) cache = argv[++i];
        else if (!strcmp(argv[i], "--from") && i + 1 < argc) from = strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--count") && i + 1 < argc) count = strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--max") && i + 1 < argc) want = strtoul(argv[++i], NULL, 10);
        else { fprintf(stderr, "usage: mkvectors_chain --node HOST --headers CACHE "
                               "--from HEIGHT [--count N] [--max V]\n"); return 2; }
    }
    if (!node || !cache || !from) { fprintf(stderr, "mkvectors_chain: --node, --headers and --from are required\n"); return 2; }
    const kw_chainparams *cp = &KW_DOGE_MAINNET;
    if (port < 0) port = cp->p2p_port;

    kw_headerstore s;
    if (!kw_headerstore_init(&s) || !kw_headerstore_load(&s, cache)) {
        fprintf(stderr, "mkvectors_chain: cannot load %s\n", cache);
        return 1;
    }
    if (from + count > s.count) { fprintf(stderr, "mkvectors_chain: the cache ends at %zu\n", s.count); return 1; }

    g_idx = (idx_entry *)calloc(IDX_SIZE, sizeof *g_idx);
    if (!g_idx) return 1;

    kw_peer p;
    if (!kw_peer_connect(&p, cp, node, port, 20) || !kw_peer_handshake(&p, 0)) {
        fprintf(stderr, "mkvectors_chain: no peer\n");
        return 1;
    }

    unsigned long emitted = 0, p2pkh = 0, p2sh = 0, blocks = 0;
    printf("# koinu sighash vectors v1: prevout scriptPubKey, input index, spending tx\n");
    printf("# read from mainnet blocks %lu..%lu, prevouts indexed from the same run\n",
           from, from + count - 1);

    for (unsigned long h = from; h < from + count && emitted < want; h++) {
        const uint8_t *blk = NULL;
        size_t blen = 0;
        if (!kw_spv_get_block(&p, s.h[h - 1].hash, &blk, &blen)) {
            fprintf(stderr, "mkvectors_chain: block %lu did not arrive\n", h);
            break;
        }
        blocks++;

        size_t off = 80;
        uint32_t version = (uint32_t)blk[0] | ((uint32_t)blk[1] << 8) |
                           ((uint32_t)blk[2] << 16) | ((uint32_t)blk[3] << 24);
        if (version & KW_BLOCK_VERSION_AUXPOW) {
            if (!kw_auxpow_parse(blk, blen, &off, NULL)) continue;
        }
        /* the transaction count, a varint */
        if (off >= blen) continue;
        uint64_t ntx = blk[off++];
        if (ntx == 0xfd) { if (off + 2 > blen) continue; ntx = (uint64_t)blk[off] | ((uint64_t)blk[off+1] << 8); off += 2; }
        else if (ntx == 0xfe) { if (off + 4 > blen) continue; ntx = 0; for (int b = 0; b < 4; b++) ntx |= (uint64_t)blk[off+b] << (8*b); off += 4; }
        else if (ntx == 0xff) { continue; }

        for (uint64_t t = 0; t < ntx && off < blen; t++) {
            kw_tx tx;
            size_t used = kw_tx_parse(blk + off, blen - off, &tx);
            if (!used) break;                       /* segwit or over a builder limit */
            const uint8_t *txraw = blk + off;
            off += used;

            uint8_t txid[32];
            if (!kw_tx_txid(&tx, txid)) continue;

            /* every spend this transaction makes, if its prevout is in the run */
            for (size_t in = 0; in < tx.nin && emitted < want; in++) {
                size_t spklen = 0;
                const uint8_t *spk = idx_get(tx.vin[in].prevout, tx.vin[in].vout, &spklen);
                if (!spk) continue;

                const uint8_t *at[8];
                size_t sz[8];
                int n = 0;
                if (!pushes(tx.vin[in].script, tx.vin[in].scriptlen, at, sz, 8, &n)) continue;
                if (n < 2) continue;

                const uint8_t *code = NULL;
                size_t codelen = 0;
                int firstsig = 0, nsig = 0;
                if (spklen == 25 && spk[0] == 0x76 && spk[1] == 0xa9) {
                    if (n != 2) continue;           /* <sig> <pubkey> */
                    code = spk; codelen = spklen;
                    firstsig = 0; nsig = 1;
                    p2pkh++;
                } else if (spklen == 23 && spk[0] == 0xa9) {
                    code = at[n - 1]; codelen = sz[n - 1];   /* the redeem script */
                    int m = 0, k = 0;
                    uint8_t keys[16][33];
                    if (!kw_script_multisig_parse(code, codelen, &m, keys, &k)) continue;
                    firstsig = 1;                   /* push 0 is the CHECKMULTISIG dummy */
                    nsig = n - 2;
                    if (nsig < 1 || sz[0] != 0) continue;
                    p2sh++;
                } else {
                    continue;
                }

                if (has_codeseparator(code, codelen)) continue;

                int ok = 1;
                for (int q = 0; q < nsig && ok; q++) {
                    const uint8_t *sig = at[firstsig + q];
                    size_t sl = sz[firstsig + q];
                    if (!usable_sig(sig, sl)) ok = 0;
                    /* FindAndDelete strips a signature that appears in its own script
                       code before hashing, which this tree does not do, so those are
                       outside what the vector would be claiming */
                    else if (contains(code, codelen, sig, sl)) ok = 0;
                }
                if (!ok) continue;

                char *spkhex = (char *)malloc(spklen * 2 + 1);
                char *txhex = (char *)malloc(used * 2 + 1);
                if (spkhex && txhex) {
                    kw_hex_encode(spk, spklen, spkhex, spklen * 2 + 1);
                    kw_hex_encode(txraw, used, txhex, used * 2 + 1);
                    printf("%s %zu %s\n", spkhex, in, txhex);
                    emitted++;
                }
                free(spkhex);
                free(txhex);
            }

            idx_put(txid, &tx);
        }
    }

    kw_peer_close(&p);
    kw_headerstore_free(&s);
    free(g_idx);
    fprintf(stderr, "%lu vectors from %lu blocks: %lu p2pkh spends and %lu p2sh seen\n",
            emitted, blocks, p2pkh, p2sh);
    return emitted ? 0 : 1;
}
