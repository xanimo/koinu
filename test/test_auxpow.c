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
#include "hex.h"
#include "pow.h"
#include "scrypt.h"
#include "sha2.h"

#include <stdio.h>
#include <stdlib.h>
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

static const char b371337[] =
    "020162000d6f03470d329026cd1fc720c0609cd378ca8691a117bd1aa46f01fb09b1a846"
    "8a15bf6f0b0e83f2e5036684169eafb9406468d4f075c999fb5b2a78fbb827ee41fb1154"
    "8441361b0000000001000000010000000000000000000000000000000000000000000000"
    "000000000000000000ffffffff380345bf09fabe6d6d980ba42120410de0554d42a5b5ee"
    "58167bcd86bf7591f429005f24da45fb51cf0800000000000000cdb1f1ff0e000000ffff"
    "ffff01800c0c2a010000001976a914aa3750aa18b8a0f3f0590731e1fab934856680cf88"
    "ac00000000b3e64e02fff596209c498f1b18f798d62f216f11c8462bf392231900000000"
    "0003a979a636db2450363972d211aee67b71387a3daaa3051be0fd260c5acd4739cd52a4"
    "18d29d8a0e56c8714c95a0dc24e1c9624480ec497fe2441941f3fee8f9481a3370c33417"
    "8415c83d1d0c2deeec727c2330617a47691fc5e79203669312d100000000036fa40307b3"
    "a439538195245b0de56a2c1db6ba3a64f8bdd2071d00bc48c841b5e77b98e5c7d6f06f92"
    "dec5cf6d61277ecb9a0342406f49f34c51ee8ce4abd678038129485de14238bd1ca12cd2"
    "de12ff0e383aee542d90437cd664ce139446a00000000002000000d2ec7dfeb7e8f43fe7"
    "7aba3368df95ac2088034420402730ee0492a2084217083411b3fc91033bfdeea339bc11"
    "b9efc986e161c703e07a9045338c165673f09940fb11548b54021b58cc9ae5";

static const char b400000[] =
    "02016200b047cc94ef6886e3e2e79226703a58841619d8fab0de523c1664517310c12818"
    "704bc78ff28bf8f7fb20a9901e2ace59db1ab634fbd41a4a74e064a29e6dd315965c2d54"
    "8a20071b0000000001000000010000000000000000000000000000000000000000000000"
    "000000000000000000ffffffff4f03e1ef09fabe6d6d4378cee85115fe9014b53a0b1d0a"
    "58b6c5677b26d8efddddcd590d129694e7a70100000000000000062f503253482f04785c"
    "2d54080800200402000000092f7374726174756d2f000000000100f2052a010000001976"
    "a914f332ec6f1729495e7edcd8ce9d887742567fe60988ac00000000ed94aa029449a3fa"
    "7684d707d04fcd11d6e0d42c2db0d1b5392a135b0b098706000000000000000000000200"
    "0000e6816ca65e5c4ae73186cea2ee263cb69e86f311fcbe07d41908f3b170bb33804bf5"
    "5dc3db4f3228ca5122eef35ea1c7bdd521bc80aa496033103e8d983fccec9d5c2d5431cf"
    "011b0cd75567";

static const char b6000000[] =
    "040162008a64527d896fcd83a29609393c2b93d4d7a2b66e147d3b76740e99584018edf9"
    "9f229be5bdfa7a0cab2d457f77fea51d8095ab4464bb2d34e686dc9ce751e70f27173e69"
    "98a32f190000000001000000010000000000000000000000000000000000000000000000"
    "000000000000000000ffffffff46031d162e04693e17272cfabe6d6d70fd25517d4bdc1f"
    "1ea323d3021ab3a2c3af17b3bfb327cd3d637b62239e90278000000000000000042f4c50"
    "2f0a16003394140200000000ffffffff02fcfa5225000000001976a91457757ed2d68143"
    "967543d7c58579c33e8984548888ac0000000000000000266a24aa21a9edef0b10b8fef1"
    "0a6b4fa521a5233f8ebb979d5bc04b34c5ffaa929c11e73269f700000000fdecf534c03f"
    "49debd89f48ef1c0b0c3be0e7d335521a046657bd585c16ae728097c29ecfcf1ad6aa9ad"
    "aa06e8767cb1c3e9468e37f8c1000a82ac6c52b2bbd17d64b5b30259718e491a8a32aa85"
    "475f5319ef9010d2de488119b7cbbdf60636648510a833d5ad3ae5dfebbabb0331fac43d"
    "e04941bd7ce2387747f16b81af92df05d2fd0342dbdc4f5d16619be0c54d2f0b882b8a55"
    "e4b03d9931b256072928a6a19e9b755e1d1c379afc61153f02c6e9adc6cbb2dc1ef30f80"
    "181c71298d3150c67579b8a611be32bca2199329abe93fd06836b80ecb1f8b573f4bbe73"
    "ff890642a34009c0c774703c144ad67ca6fa9d51dea27b408ac39e3628cd2229cc60827f"
    "d0b96e5df5607879e697da2ddda9b973f01f1069b84a892c5a74fe3449a9e3bebcf7c97b"
    "481ed46865932ee173ce4edc3e39f36c980db713c5866d7a804b5c000000000700000000"
    "00000000000000000000000000000000000000000000000000000000e2f61c3f71d1defd"
    "3fa999dfa36953755c690689799962b48bebd836974e8cf97d24db2bfa41474bfb2f877d"
    "688fac5faa5e10a2808cf9de307370b93352e54894857d3e08918f70395d9206410fbfa9"
    "42f1a889aa5ab8188ec33c2f6e207dc719bf1203d3bf48393c69cc25598914bb9e0d302f"
    "363d9825dba0b9fb959ca33bf8d91ce3438734424054e36bf90938a97dd9ca07683d5b4c"
    "6bf1d247e2f916a6f1c4426d56eb9d5b96424bf58038c58348f735582436e29d5aab31fa"
    "7fb141753800000000000020c385853fe08625a2b1e315f742d2886678e7ecbf34e3783e"
    "120f192791dbc430a96a4a3150abf77282cd423f63a81551dd25a382528adfe3cd1cf431"
    "941923ca22173e69245b25193b95b054";

/* 6350067, whose parent coinbase carries a witness. Every litecoin block since
   2017 does, and no fixture here did before: the txid in the parent's merkle tree
   is hashed over the transaction with the witness taken out, and hashing the bytes
   as they arrive gives the wtxid instead. */
static const char b6350067[] =
    "04016200d297b1959fd937b90213159b968476ec7294bcf105457af288a273e2"
    "6ad5b7d092ae68b16aada6bd74396ce7f97397732cfe18a65f947563d810bcf7"
    "09cfcc2b5ad2906a914375190000000002000000000101000000000000000000"
    "0000000000000000000000000000000000000000000000ffffffff4803675530"
    "045ad2906a08656d63645f5233302cfabe6d6dc6f023dbf44cd49f8cadf794d4"
    "92bd922fb9c9b85dc2fd904904415dd29f99422000000000000000080000b665"
    "720100000000000002c887432500000000160014a0210a92fdaef52ea18f0c8f"
    "db9246a751617b520000000000000000266a24aa21a9ed780b1055ac2738f29d"
    "26238414fb375a1104bcdced95db883a525f476ca97f47012000000000000000"
    "00000000000000000000000000000000000000000000000000000000002d72bb"
    "e164be1617b2d95be923288fb19f78dbb974970bf0c0046c64c0825eb407fcfe"
    "95272909afb1eeaaa29ec6336a095ab698faa3e62288f3ac30a43ac0f32d0eca"
    "b9d70b7b1d60622e4ebc9e953cd89834aa379f52affc2059dd7427d7b2ecb871"
    "0d42c876cc8eb5f5864095ca276ac3263b19207701d1222ed9754f618aea4aeb"
    "4d9623b46a6e990612a0f3062606a2e0cf704664e55fa1581de5f1bcb21a02a7"
    "0d261fc2b7b73a1b0dcccfb55cb4ea552da80398866e51de39de5dee6be42115"
    "e08c1787706495556dfbd8c5bfd38badf24272fe59fc010d8509a391fcf8dfd4"
    "a97ae782e12eb916f94350a367875a92a76a6e26215218ade13d17395e550000"
    "0000050000000000000000000000000000000000000000000000000000000000"
    "000000e2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd83697"
    "4e8cf9fdf847b5dc6d891bb776d6e14c6f6c8a917d23cfc802b2fbee657d9c5f"
    "8f138dd4f12ac4c750a2a5fa4eed622b4d34b180768674d7618f9e6a8a55067e"
    "eff524380a3ac1b57415068aae1a70ea4a36ae75db9860134e56a830c5c57670"
    "88420a1800000000000020b74fe8cd4076f798b2b0dd3bcf8a8c3541b419d77b"
    "19d8b0f9ef640b35c90c729c82598c8d418a77167e06c104fd0f1f825f7d4c2f"
    "2c276acc071542f621b8ce34d2906a657b2f1920d09c9e";

/* Real proofs, fetched from a peer with test/net_auxpow.c. Each is the block's
   80-byte header followed by its AuxPoW blob and nothing else, so the test derives
   the hash and the target from the same bytes a peer sent. Chosen for their shapes:
   the first merged-mined block, one whose branches are both empty, one sitting in
   slot 56 of a 128-leaf tree, which is the only real check there is of the slot
   derivation, and one whose parent coinbase carries a witness. */
static void real_proofs(void)
{
    static const struct { const char *what; const char *hex; } real[] = {
        { "371337, the first merged-mined block", b371337 },
        { "400000, both branches empty",          b400000 },
        { "6000000, slot 56 of 128 leaves",       b6000000 },
        { "6350067, segwit parent coinbase",      b6350067 }
    };

    for (size_t i = 0; i < sizeof real / sizeof *real; i++) {
        size_t hexlen = strlen(real[i].hex), n = hexlen / 2;
        uint8_t *raw = (uint8_t *)malloc(n);
        if (!raw) { bad("out of memory"); return; }
        if (!kw_hex_decode(real[i].hex, hexlen, raw, n)) { bad("bad fixture hex"); free(raw); continue; }

        uint8_t id[32];
        sha256d(raw, 80, id);
        uint32_t bits = kw_header_bits(raw);
        uint32_t version = (uint32_t)raw[0] | ((uint32_t)raw[1] << 8) |
                           ((uint32_t)raw[2] << 16) | ((uint32_t)raw[3] << 24);
        if (!(version & 0x100u)) { bad("a real proof's block is not marked auxpow"); free(raw); continue; }

        size_t off = 80;
        kw_auxpow ap;
        if (!kw_auxpow_parse(raw, n, &off, &ap)) {
            fprintf(stderr, "FAIL: %s did not parse\n", real[i].what);
            fail = 1; free(raw); continue;
        }
        if (off != n) { fprintf(stderr, "FAIL: %s left %zu bytes over\n", real[i].what, n - off); fail = 1; }
        if (!kw_auxpow_check(&ap, id, bits, KW_AUXPOW_CHAIN_ID, NULL)) {
            fprintf(stderr, "FAIL: %s does not verify\n", real[i].what);
            fail = 1; free(raw); continue;
        }

        /* A merged-mined block's own header does not meet its target: that is what
           makes the parent's work necessary rather than decorative. */
        uint8_t own[32];
        if (kw_scrypt_pow(raw, own, NULL) && kw_pow_check(own, bits)) {
            fprintf(stderr, "FAIL: %s meets its own target, so it needs no parent\n", real[i].what);
            fail = 1;
        }

        /* one byte of the parent header, and the proof is worthless */
        size_t parent_at = n - 80;
        raw[parent_at + 76] ^= 1;                       /* the parent's nonce */
        off = 80;
        if (kw_auxpow_parse(raw, n, &off, &ap) &&
            kw_auxpow_check(&ap, id, bits, KW_AUXPOW_CHAIN_ID, NULL)) {
            fprintf(stderr, "FAIL: %s verified with the parent's nonce moved\n", real[i].what);
            fail = 1;
        }
        raw[parent_at + 76] ^= 1;

        /* and the target still has to be the one the chain asked for */
        off = 80;
        if (kw_auxpow_parse(raw, n, &off, &ap) &&
            kw_auxpow_check(&ap, id, 0x1a000001u, KW_AUXPOW_CHAIN_ID, NULL)) {
            fprintf(stderr, "FAIL: %s met a target far above its own\n", real[i].what);
            fail = 1;
        }
        free(raw);
    }
}

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
    real_proofs();
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
    printf("auxpow ok: 4 real mainnet proofs verify and fail with one bit of the parent\n"
           "  moved, none meets its own target, and 9 tampers on a built proof plus\n"
           "  truncation and an impossible target are refused\n");
    return 0;
}
