/* koinu.dog - merged-mining proof parsing and checking
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * The blob's layout lives here and nowhere else: net/headers.c steps over one by
 * calling the parser with no destination, so a sync that does not verify and a
 * validator that does read the same definition of the format. */

#include "auxpow.h"
#include "pow.h"
#include "scrypt.h"
#include "sha2.h"

#include <string.h>

/* ── reading ─────────────────────────────────────────────────────────────
   A bounds-checked cursor: every step sets (bad) rather than reading past the
   end, and the caller checks once at the end. */
typedef struct { const uint8_t *p; size_t len, off; int bad; } R;

static uint64_t r_varint(R *r)
{
    if (r->bad || r->off >= r->len) { r->bad = 1; return 0; }
    uint8_t t = r->p[r->off++];
    uint64_t v = 0;
    size_t n = t < 0xfd ? 0 : (t == 0xfd ? 2 : (t == 0xfe ? 4 : 8));
    if (n == 0) return t;
    if (r->off + n > r->len) { r->bad = 1; return 0; }
    for (size_t i = 0; i < n; i++) v |= (uint64_t)r->p[r->off + i] << (8 * i);
    r->off += n;
    return v;
}

static void r_skip(R *r, uint64_t n)
{
    if (r->bad || n > r->len - r->off) { r->bad = 1; return; }
    r->off += (size_t)n;
}

static const uint8_t *r_take(R *r, uint64_t n)
{
    if (r->bad || n > r->len - r->off) { r->bad = 1; return NULL; }
    const uint8_t *at = r->p + r->off;
    r->off += (size_t)n;
    return at;
}

/* a vector<uint256>, into (out) when there is somewhere to put it */
static size_t r_hashvec(R *r, uint8_t (*out)[32], size_t cap)
{
    uint64_t n = r_varint(r);
    if (r->bad) return 0;
    if (out && n > cap) { r->bad = 1; return 0; }       /* longer than any real proof */
    for (uint64_t i = 0; i < n && !r->bad; i++) {
        const uint8_t *h = r_take(r, 32);
        if (h && out) memcpy(out[i], h, 32);
    }
    return r->bad ? 0 : (size_t)n;
}

static int32_t r_int32(R *r)
{
    const uint8_t *p = r_take(r, 4);
    if (!p) return -1;
    return (int32_t)((uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                     ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
}

/* The parent's coinbase. Its bytes are its txid's preimage, and its first input's
   scriptSig is where the commitment sits, so both are recorded rather than
   skipped. */
static void r_tx(R *r, kw_auxpow *ap)
{
    size_t start = r->off;
    r_skip(r, 4);                                   /* version */
    uint64_t nin = r_varint(r);
    int segwit = 0;
    size_t vin_start = start + 4;
    if (nin == 0) {                                 /* marker, flag, then the real vin */
        r_skip(r, 1);
        segwit = 1;
        vin_start = r->off;                         /* the txid covers neither */
        nin = r_varint(r);
    }
    for (uint64_t i = 0; i < nin && !r->bad; i++) {
        r_skip(r, 36);                              /* prevout */
        uint64_t sl = r_varint(r);
        const uint8_t *s = r_take(r, sl);
        if (i == 0 && ap && s) { ap->script = s; ap->script_len = (size_t)sl; }
        r_skip(r, 4);                               /* sequence */
    }
    uint64_t nout = r_varint(r);
    for (uint64_t i = 0; i < nout && !r->bad; i++) {
        r_skip(r, 8);                               /* value */
        r_skip(r, r_varint(r));                     /* scriptPubKey */
    }
    size_t vout_end = r->off;
    if (segwit)
        for (uint64_t i = 0; i < nin && !r->bad; i++) {
            uint64_t items = r_varint(r);
            for (uint64_t j = 0; j < items && !r->bad; j++) r_skip(r, r_varint(r));
        }
    size_t lock_start = r->off;
    r_skip(r, 4);                                   /* locktime */
    if (ap && !r->bad) {
        ap->coinbase = r->p + start;
        ap->coinbase_len = r->off - start;
        if (segwit) {
            ap->strip[0].p = r->p + start;          ap->strip[0].len = 4;
            ap->strip[1].p = r->p + vin_start;      ap->strip[1].len = vout_end - vin_start;
            ap->strip[2].p = r->p + lock_start;     ap->strip[2].len = 4;
            ap->nstrip = 3;
        } else {
            ap->strip[0].p = r->p + start;          ap->strip[0].len = r->off - start;
            ap->nstrip = 1;
        }
    }
}

int kw_auxpow_parse(const uint8_t *in, size_t len, size_t *off, kw_auxpow *ap)
{
    if (!in || !off || *off > len) return 0;
    R r = { in, len, *off, 0 };
    if (ap) memset(ap, 0, sizeof *ap);

    r_tx(&r, ap);                                   /* CMerkleTx.tx */
    r_skip(&r, 32);                                 /* CMerkleTx.hashBlock */
    size_t nm = r_hashvec(&r, ap ? ap->merkle : NULL, KW_AUXPOW_MAX_MERKLE);
    int32_t idx = r_int32(&r);                      /* CMerkleTx.nIndex */
    size_t nc = r_hashvec(&r, ap ? ap->chain : NULL, KW_AUXPOW_MAX_CHAIN);
    int32_t cidx = r_int32(&r);                     /* nChainIndex */
    const uint8_t *parent = r_take(&r, 80);         /* the parent's pure header */

    if (r.bad) return 0;
    if (ap) {
        ap->nmerkle = nm;
        ap->index = idx;
        ap->nchain = nc;
        ap->chain_index = cidx;
        ap->parent = parent;
    }
    *off = r.off;
    return 1;
}

/* ── checking ────────────────────────────────────────────────────────────── */

static void sha256d(const uint8_t *in, size_t len, uint8_t out[32])
{
    uint8_t once[32];
    kw_sha256(in, len, once);
    kw_sha256(once, 32, out);
}

/* Walk a merkle branch up from (h), taking the left or right side at each level
   from the bits of (index), lowest first. */
static void merkle_up(uint8_t h[32], const uint8_t (*branch)[32], size_t n, uint32_t index)
{
    for (size_t i = 0; i < n; i++) {
        uint8_t cat[64];
        if (index & 1) { memcpy(cat, branch[i], 32); memcpy(cat + 32, h, 32); }
        else           { memcpy(cat, h, 32);         memcpy(cat + 32, branch[i], 32); }
        sha256d(cat, 64, h);
        index >>= 1;
    }
}

uint32_t kw_auxpow_expected_index(uint32_t nonce, int32_t chain_id, unsigned h)
{
    /* Deliberately the same wrapping arithmetic as the reference: it overflows,
       and the result is taken modulo a power of two, so the overflow is part of
       the answer rather than a bug in it. */
    uint32_t rand = nonce;
    rand = rand * 1103515245u + 12345u;
    rand += (uint32_t)chain_id;
    rand = rand * 1103515245u + 12345u;
    return h >= 32 ? 0 : rand % (1u << h);
}

/* first occurrence of (needle) in (hay), or -1 */
static long find(const uint8_t *hay, size_t hlen, const uint8_t *needle, size_t nlen)
{
    if (nlen == 0 || hlen < nlen) return -1;
    for (size_t i = 0; i + nlen <= hlen; i++)
        if (memcmp(hay + i, needle, nlen) == 0) return (long)i;
    return -1;
}

static uint32_t rd32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int kw_auxpow_check_structure(const kw_auxpow *ap, const uint8_t aux_hash[32],
                              int32_t chain_id)
{
    static const uint8_t tag[4] = { 0xfa, 0xbe, 'm', 'm' };

    if (!ap || !aux_hash || !ap->parent || !ap->coinbase || !ap->script) return 0;
    if (ap->index != 0) return 0;                   /* the coinbase is transaction 0 */
    if (ap->chain_index < 0) return 0;
    if (ap->nchain > KW_AUXPOW_MAX_CHAIN) return 0;

    /* the parent must be on another chain, or the work is not borrowed at all */
    int32_t parent_chain = (int32_t)(rd32le(ap->parent) >> 16);
    if (parent_chain == chain_id) return 0;

    /* this block's hash has to sit in the tree the parent's coinbase commits to */
    uint8_t root[32];
    memcpy(root, aux_hash, 32);
    merkle_up(root, ap->chain, ap->nchain, (uint32_t)ap->chain_index);

    /* the commitment is written big-endian in the script, the reverse of a hash */
    uint8_t want[32];
    for (int i = 0; i < 32; i++) want[i] = root[31 - i];

    /* and the coinbase has to be in the parent's own merkle tree, under its txid.
       Hashing the bytes as they arrived gives the wtxid when the parent chain has
       segwit, which is every litecoin block since 2017: the merkle root then never
       matches and the proof is refused for a reason that has nothing to do with it. */
    uint8_t cb[32];
    if (ap->nstrip < 1) return 0;
    kw_sha256_ctx sc;
    uint8_t once[32];
    kw_sha256_init(&sc);
    for (int i = 0; i < ap->nstrip; i++) kw_sha256_update(&sc, ap->strip[i].p, ap->strip[i].len);
    kw_sha256_final(&sc, once);
    kw_sha256(once, 32, cb);
    merkle_up(cb, ap->merkle, ap->nmerkle, (uint32_t)ap->index);
    if (memcmp(cb, ap->parent + 36, 32) != 0) return 0;   /* parent hashMerkleRoot */

    long at = find(ap->script, ap->script_len, want, 32);
    if (at < 0) return 0;
    long head = find(ap->script, ap->script_len, tag, sizeof tag);
    if (head >= 0) {
        /* one tag only, and immediately before the commitment: otherwise a second
           chain's root could be appended and the same work spent twice */
        if (find(ap->script + head + 1, ap->script_len - (size_t)head - 1,
                 tag, sizeof tag) >= 0) return 0;
        if (head + (long)sizeof tag != at) return 0;
    } else if (at > 20) {
        /* older proofs carry no tag, so the commitment has to start early enough
           that the bytes before it cannot be a payload of their own */
        return 0;
    }

    /* the tree's size and the nonce that fixes our slot in it follow the root */
    size_t after = (size_t)at + 32;
    if (ap->script_len - after < 8) return 0;
    uint32_t size = rd32le(ap->script + after);
    uint32_t nonce = rd32le(ap->script + after + 4);
    if (ap->nchain >= 32 || size != (1u << ap->nchain)) return 0;
    if ((uint32_t)ap->chain_index != kw_auxpow_expected_index(nonce, chain_id,
                                                              (unsigned)ap->nchain))
        return 0;

    return 1;
}

int kw_auxpow_check(const kw_auxpow *ap, const uint8_t aux_hash[32], uint32_t aux_bits,
                    int32_t chain_id, void *scratch)
{
    if (!kw_auxpow_check_structure(ap, aux_hash, chain_id)) return 0;

    /* and the parent's own work has to meet the target this chain asked for */
    uint8_t pow[32];
    if (!kw_scrypt_pow(ap->parent, pow, scratch)) return 0;
    return kw_pow_check(pow, aux_bits);
}
