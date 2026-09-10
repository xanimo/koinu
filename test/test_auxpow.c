/* koinu.dog - merged-mining proof tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * The proof is built here rather than captured from the chain, which is worth being
 * plain about: this checks that the rules are enforced and that the pieces hash
 * together the way src/auxpow.cpp says, not that the field order matches a real
 * blob. What does check the field order is net/headers.c, which steps over a real
 * proof by calling the same parser, and did so over six million mainnet headers
 * before this test existed.
 *
 * The target is set so close to 2^256 that the parent's work passes trivially: what
 * is under test here is the structure. test/test_pow.c is where a real header meets
 * a real target.
 *
 * Every rule gets a tamper: move the tag, add a second one, bend the index, the
 * size, the chain id, the coinbase's position, and the committed hash. A proof that
 * still verifies after any of those is a proof that checks nothing. */

#include "auxpow.h"
#include "pow.h"
#include "sha2.h"

#include <stdio.h>
#include <string.h>

static int fail;

static void bad(const char *what)
{
    fprintf(stderr, "FAIL: %s\n", what);
    fail = 1;
}

static void sha256d(const uint8_t *in, size_t len, uint8_t out[32])
{
    uint8_t once[32];
    kw_sha256(in, len, once);
    kw_sha256(once, 32, out);
}

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

/* a little-endian writer, since every count and length in a blob is one */
static uint8_t *put32(uint8_t *p, uint32_t v)
{
    *p++ = (uint8_t)v; *p++ = (uint8_t)(v >> 8);
    *p++ = (uint8_t)(v >> 16); *p++ = (uint8_t)(v >> 24);
    return p;
}

#define AUX_BITS 0x2100ffffu        /* a target just under 2^256 */
#define NCHAIN   2                  /* a four-leaf chain tree */

/* Everything a proof is made of, kept so a test can bend one piece and rebuild. */
struct built {
    uint8_t aux[80];                /* the dogecoin header being proved */
    uint8_t aux_hash[32];
    uint8_t chain_branch[NCHAIN][32];
    uint32_t chain_index, nonce, size;
    uint8_t cb_branch[1][32];
    uint8_t blob[512];
    size_t  blob_len;
    size_t  script_at;              /* where the scriptSig starts inside blob */
    int32_t parent_chain;
    int     tag;                    /* write the merged-mining tag */
    int     tag_gap;                /* bytes of padding between tag and root */
    int     twice;                  /* write the tag a second time */
    int     lead;                   /* bytes before the root when there is no tag */
    uint32_t claim_size;            /* the size to write, 0 for the honest one */
    int32_t claim_index;            /* the index to write, -2 for the honest one */
    int     break_cb;               /* corrupt the coinbase's place in the parent */
    int     break_commit;           /* commit to a different aux hash */
    int32_t nindex;
};

static void build(struct built *b)
{
    memset(b->aux, 0, sizeof b->aux);
    put32(b->aux, 0x00620102u);                   /* auxpow bit, chain id 0x62 */
    put32(b->aux + 68, 1700000000u);
    put32(b->aux + 72, AUX_BITS);
    sha256d(b->aux, 80, b->aux_hash);

    for (size_t i = 0; i < NCHAIN; i++) memset(b->chain_branch[i], 0xa0 + (int)i, 32);
    memset(b->cb_branch[0], 0xcc, 32);
    b->size = 1u << NCHAIN;
    b->chain_index = kw_auxpow_expected_index(b->nonce, KW_AUXPOW_CHAIN_ID, NCHAIN);

    /* The commitment is built with the index the blob will claim, not the derived
       one. Otherwise claiming a wrong index also breaks the tree, the root lookup
       rejects it first, and the slot rule is never reached: mutating that rule away
       left this test still passing until the two were separated. */
    uint32_t use = b->claim_index == -2 ? b->chain_index : (uint32_t)b->claim_index;
    uint8_t root[32];
    memcpy(root, b->aux_hash, 32);
    if (b->break_commit) root[0] ^= 1;
    merkle_up(root, b->chain_branch, NCHAIN, use);
    uint8_t commit[32];
    for (int i = 0; i < 32; i++) commit[i] = root[31 - i];

    /* the parent's coinbase scriptSig */
    uint8_t script[128];
    size_t sl = 0;
    if (!b->tag) for (int i = 0; i < b->lead; i++) script[sl++] = 0x51;
    if (b->tag) {
        static const uint8_t tag[4] = { 0xfa, 0xbe, 'm', 'm' };
        memcpy(script + sl, tag, 4); sl += 4;
        if (b->twice) { memcpy(script + sl, tag, 4); sl += 4; }
        for (int i = 0; i < b->tag_gap; i++) script[sl++] = 0x51;
    }
    memcpy(script + sl, commit, 32); sl += 32;
    sl = (size_t)(put32(script + sl, b->claim_size ? b->claim_size : b->size) - script);
    sl = (size_t)(put32(script + sl, b->nonce) - script);

    /* the coinbase transaction, one input and one output */
    uint8_t cbtx[256];
    size_t n = 0;
    n = (size_t)(put32(cbtx + n, 1) - cbtx);      /* version */
    cbtx[n++] = 1;                                /* one input */
    memset(cbtx + n, 0, 36); n += 36;             /* prevout */
    cbtx[n++] = (uint8_t)sl;
    size_t script_in_tx = n;
    memcpy(cbtx + n, script, sl); n += sl;
    n = (size_t)(put32(cbtx + n, 0xffffffffu) - cbtx);
    cbtx[n++] = 1;                                /* one output */
    memset(cbtx + n, 0, 8); n += 8;               /* value */
    cbtx[n++] = 0;                                /* empty scriptPubKey */
    n = (size_t)(put32(cbtx + n, 0) - cbtx);      /* locktime */

    /* the parent header commits to the coinbase through its own merkle branch */
    uint8_t cbid[32];
    sha256d(cbtx, n, cbid);
    uint8_t proot[32];
    memcpy(proot, cbid, 32);
    merkle_up(proot, b->cb_branch, 1, 0);
    if (b->break_cb) proot[0] ^= 1;

    uint8_t parent[80];
    memset(parent, 0, sizeof parent);
    put32(parent, (uint32_t)(b->parent_chain << 16) | 1u);
    memcpy(parent + 36, proot, 32);
    put32(parent + 68, 1700000001u);
    put32(parent + 72, AUX_BITS);

    /* assemble: coinbase, its block hash, its branch, index, chain branch, index,
       then the parent's header */
    uint8_t *p = b->blob;
    memcpy(p, cbtx, n); p += n;
    b->script_at = script_in_tx;
    memset(p, 0x77, 32); p += 32;                 /* hashBlock, unchecked */
    *p++ = 1;
    memcpy(p, b->cb_branch[0], 32); p += 32;
    p = put32(p, (uint32_t)b->nindex);
    *p++ = NCHAIN;
    for (size_t i = 0; i < NCHAIN; i++) { memcpy(p, b->chain_branch[i], 32); p += 32; }
    p = put32(p, use);
    memcpy(p, parent, 80); p += 80;
    b->blob_len = (size_t)(p - b->blob);
}

/* build with (edit) applied, parse, and return whether the proof verifies */
static int verifies(void (*edit)(struct built *), int *parsed)
{
    struct built b;
    memset(&b, 0, sizeof b);
    b.nonce = 0x12345678u;
    b.tag = 1;
    b.parent_chain = 0;
    b.claim_index = -2;
    b.nindex = 0;
    if (edit) edit(&b);
    build(&b);

    kw_auxpow ap;
    size_t off = 0;
    if (!kw_auxpow_parse(b.blob, b.blob_len, &off, &ap)) { if (parsed) *parsed = 0; return 0; }
    if (parsed) *parsed = 1;
    if (off != b.blob_len) { bad("the parser did not consume the whole blob"); return 0; }
    return kw_auxpow_check(&ap, b.aux_hash, AUX_BITS, KW_AUXPOW_CHAIN_ID, NULL);
}

static void must_fail(const char *what, void (*edit)(struct built *))
{
    int parsed = 0;
    if (verifies(edit, &parsed)) bad(what);
}

static void gap(struct built *b)      { b->tag_gap = 3; }
static void two_tags(struct built *b) { b->twice = 1; }
static void no_tag_early(struct built *b) { b->tag = 0; b->lead = 4; }
static void no_tag_late(struct built *b)  { b->tag = 0; b->lead = 21; }
static void wrong_size(struct built *b)   { b->claim_size = 8; }
static void wrong_index(struct built *b)  { b->claim_index = 3; }
static void our_chain(struct built *b)    { b->parent_chain = KW_AUXPOW_CHAIN_ID; }
static void not_coinbase(struct built *b) { b->nindex = 1; }
static void cb_not_in_tree(struct built *b) { b->break_cb = 1; }
static void wrong_commit(struct built *b)   { b->break_commit = 1; }

int main(void)
{
    /* the index rule has no data to check it against, so it is checked against the
       reference's own arithmetic, including the overflow it relies on */
    if (kw_auxpow_expected_index(0, 0, 0) != 0) bad("a one-leaf tree has one slot");
    if (kw_auxpow_expected_index(0x12345678u, KW_AUXPOW_CHAIN_ID, 2) >= 4)
        bad("an index must be inside its tree");
    {
        uint32_t r = 0x12345678u;
        r = r * 1103515245u + 12345u;
        r += KW_AUXPOW_CHAIN_ID;
        r = r * 1103515245u + 12345u;
        if (kw_auxpow_expected_index(0x12345678u, KW_AUXPOW_CHAIN_ID, 2) != r % 4)
            bad("the slot is not the reference's arithmetic");
    }

    int parsed = 0;
    if (!verifies(NULL, &parsed)) bad("an honest proof must verify");
    if (!parsed) bad("an honest proof must parse");

    /* the tag must sit immediately before the commitment, and only once */
    must_fail("a gap between the tag and the commitment was accepted", gap);
    must_fail("two merged-mining tags were accepted", two_tags);
    /* without a tag the commitment has to start in the first 20 bytes */
    { int p2 = 0; if (!verifies(no_tag_early, &p2)) bad("a tagless proof early in the script must verify"); }
    must_fail("a tagless commitment past byte 20 was accepted", no_tag_late);

    must_fail("a tree size that does not match the branch was accepted", wrong_size);
    must_fail("a slot other than the derived one was accepted", wrong_index);
    must_fail("a parent on our own chain was accepted", our_chain);
    must_fail("a non-coinbase index was accepted", not_coinbase);
    must_fail("a coinbase outside the parent's merkle tree was accepted", cb_not_in_tree);
    must_fail("a commitment to a different block was accepted", wrong_commit);

    /* a truncated blob must be refused rather than read past its end */
    {
        struct built b;
        memset(&b, 0, sizeof b);
        b.nonce = 1; b.tag = 1; b.claim_index = -2;
        build(&b);
        for (size_t cut = 1; cut < b.blob_len; cut += 7) {
            kw_auxpow ap;
            size_t off = 0;
            if (kw_auxpow_parse(b.blob, cut, &off, &ap) && off > cut)
                { bad("a truncated blob parsed past its end"); break; }
        }
    }

    /* and the target still has to be met: a target of 1 cannot be */
    {
        struct built b;
        memset(&b, 0, sizeof b);
        b.nonce = 1; b.tag = 1; b.claim_index = -2;
        build(&b);
        kw_auxpow ap;
        size_t off = 0;
        if (kw_auxpow_parse(b.blob, b.blob_len, &off, &ap) &&
            kw_auxpow_check(&ap, b.aux_hash, 0x01000001u, KW_AUXPOW_CHAIN_ID, NULL))
            bad("the parent met a target of one");
    }

    if (fail) return 1;
    printf("auxpow ok: an honest proof verifies, the slot matches the reference\n"
           "  arithmetic, and 9 tampers plus truncation and an impossible target are refused\n");
    return 0;
}
