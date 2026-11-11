/* The rule a fetched anchor table has to satisfy. Nothing fetches one yet, so
   this is the whole of what pins the rule. */
#include <stdio.h>
#include <string.h>

#include "cfanchors.h"
#include "chainparams.h"
#include "hex.h"

/* The two real mainnet anchors this release pins, in internal order. */
static void compiled(uint32_t h, uint8_t out[32])
{
    for (size_t i = 0; i < KW_DOGE_MAINNET.ncfcheckpoints; i++) {
        if (KW_DOGE_MAINNET.cfcheckpoints[i].height != h) continue;
        uint8_t d[32];
        kw_hex_decode(KW_DOGE_MAINNET.cfcheckpoints[i].header, 64, d, sizeof d);
        for (int k = 0; k < 32; k++) out[k] = d[31 - k];
        return;
    }
    memset(out, 0, 32);
}

static size_t build(uint8_t *buf, uint32_t magic, const kw_cfanchor *a, uint32_t n)
{
    memcpy(buf, "KWCA", 4);
    buf[4] = 1; buf[5] = buf[6] = buf[7] = 0;
    for (int i = 0; i < 4; i++) buf[8 + i]  = (uint8_t)(magic >> (8 * i));
    for (int i = 0; i < 4; i++) buf[12 + i] = (uint8_t)(n >> (8 * i));
    for (uint32_t i = 0; i < n; i++) {
        uint8_t *r = buf + 16 + i * 36;
        for (int k = 0; k < 4; k++) r[k] = (uint8_t)(a[i].height >> (8 * k));
        memcpy(r + 4, a[i].header, 32);
    }
    return 16 + (size_t)n * 36;
}

int main(void)
{
    const kw_chainparams *cp = &KW_DOGE_MAINNET;
    uint32_t newest = 0;
    for (size_t i = 0; i < cp->ncfcheckpoints; i++)
        if (cp->cfcheckpoints[i].height > newest) newest = cp->cfcheckpoints[i].height;
    if (!newest) { fprintf(stderr, "FAIL: mainnet pins no anchors\n"); return 1; }

    /* A table that agrees about a height this release pins and reaches past the
       newest one. That is the only shape that may be adopted. */
    kw_cfanchor a[4];
    a[0].height = 6440000; compiled(6440000, a[0].header);
    a[1].height = newest;  compiled(newest,  a[1].header);
    a[2].height = newest + 10000; memset(a[2].header, 0x11, 32);
    a[3].height = newest + 20000; memset(a[3].header, 0x22, 32);

    uint8_t buf[16 + 4 * 36];
    size_t n = build(buf, cp->magic, a, 4);

    kw_cfanchor got[8];
    long parsed = kw_cfanchors_parse(buf, n, cp->magic, got, 8);
    if (parsed != 4) { fprintf(stderr, "FAIL: parse returned %ld, want 4\n", parsed); return 1; }

    uint32_t from = 0;
    if (!kw_cfanchors_extends(cp, got, 4, &from)) {
        fprintf(stderr, "FAIL: a table agreeing with this release was refused\n"); return 1; }
    if (from != newest + 10000) {
        fprintf(stderr, "FAIL: new entries start at %u, want %u\n", from, newest + 10000); return 1; }

    /* One byte wrong at a height this release pins kills the whole table, not
       just that entry. */
    {
        kw_cfanchor bad[4]; memcpy(bad, got, sizeof bad);
        bad[0].header[31] ^= 0x01;
        if (kw_cfanchors_extends(cp, bad, 4, &from)) {
            fprintf(stderr, "FAIL: a table contradicting a pinned anchor was accepted\n");
            return 1; }
    }

    /* No shared height is not evidence of anything, however well-formed. */
    {
        kw_cfanchor only_new[2] = { got[2], got[3] };
        if (kw_cfanchors_extends(cp, only_new, 2, &from)) {
            fprintf(stderr, "FAIL: a table sharing no height with this release was "
                            "accepted\n"); return 1; }
    }

    /* Reaching no higher than the floor adds nothing. */
    {
        kw_cfanchor low[2] = { got[0], got[1] };
        if (kw_cfanchors_extends(cp, low, 2, &from)) {
            fprintf(stderr, "FAIL: a table reaching no higher than the newest anchor was "
                            "accepted\n"); return 1; }
    }

    /* A new pin below the floor, at a height this release does not pin, must not
       become one. The table is still adopted for what is above the floor. */
    {
        kw_cfanchor sneak[5];
        sneak[0] = got[0];
        sneak[1].height = 6440001; memset(sneak[1].header, 0xee, 32);
        sneak[2] = got[1]; sneak[3] = got[2]; sneak[4] = got[3];
        uint32_t f = 0;
        if (!kw_cfanchors_extends(cp, sneak, 5, &f)) {
            fprintf(stderr, "FAIL: an entry below the floor should be ignored, not fatal\n");
            return 1; }
        if (f != newest + 10000) {
            fprintf(stderr, "FAIL: an entry below the floor was treated as new (%u)\n", f);
            return 1; }
    }

    /* Omitting a pinned height is not a contradiction: regenerating drops the
       previous run's tip, which lands on no multiple of the spacing. */
    {
        kw_cfanchor without_tip[3] = { got[0], got[2], got[3] };
        uint32_t f = 0;
        if (!kw_cfanchors_extends(cp, without_tip, 3, &f)) {
            fprintf(stderr, "FAIL: a table omitting a pinned height was refused\n"); return 1; }
    }

    /* Parse rejects what it should. */
    {
        uint8_t b[sizeof buf]; size_t bn;
        kw_cfanchor o[8];

        bn = build(b, cp->magic, a, 4); b[0] = 'X';
        if (kw_cfanchors_parse(b, bn, cp->magic, o, 8) >= 0) {
            fprintf(stderr, "FAIL: a bad tag parsed\n"); return 1; }

        bn = build(b, cp->magic, a, 4); b[4] = 2;
        if (kw_cfanchors_parse(b, bn, cp->magic, o, 8) >= 0) {
            fprintf(stderr, "FAIL: an unknown version parsed\n"); return 1; }

        bn = build(b, cp->magic, a, 4); b[5] = 1;
        if (kw_cfanchors_parse(b, bn, cp->magic, o, 8) >= 0) {
            fprintf(stderr, "FAIL: a set reserved byte parsed\n"); return 1; }

        bn = build(b, cp->magic, a, 4);
        if (kw_cfanchors_parse(b, bn, KW_DOGE_TESTNET.magic, o, 8) >= 0) {
            fprintf(stderr, "FAIL: a mainnet table parsed as testnet\n"); return 1; }

        /* a count that overruns the buffer */
        bn = build(b, cp->magic, a, 4); b[12] = 9;
        if (kw_cfanchors_parse(b, bn, cp->magic, o, 8) >= 0) {
            fprintf(stderr, "FAIL: a count past the buffer parsed\n"); return 1; }

        bn = build(b, cp->magic, a, 4);
        if (kw_cfanchors_parse(b, bn - 1, cp->magic, o, 8) >= 0 ||
            kw_cfanchors_parse(b, bn, cp->magic, o, 3) >= 0) {
            fprintf(stderr, "FAIL: a short buffer or an undersized array parsed\n"); return 1; }

        /* Bytes after the last record. Not the same case as a short buffer: a
           reader that only checks there is enough accepts this and says nothing
           about what the extra bytes were. */
        {
            uint8_t t[sizeof buf + 8];
            size_t tn = build(t, cp->magic, a, 4);
            memset(t + tn, 0xcd, 8);
            if (kw_cfanchors_parse(t, tn + 8, cp->magic, o, 8) >= 0) {
                fprintf(stderr, "FAIL: trailing bytes parsed\n"); return 1; }
        }

        /* heights that do not ascend */
        kw_cfanchor dup[2] = { a[0], a[0] };
        bn = build(b, cp->magic, dup, 2);
        if (kw_cfanchors_parse(b, bn, cp->magic, o, 8) >= 0) {
            fprintf(stderr, "FAIL: a repeated height parsed\n"); return 1; }
    }

    /* A network pinning nothing cannot check a candidate, so it refuses. */
    {
        uint32_t f = 0;
        if (kw_cfanchors_extends(&KW_DOGE_REGTEST, got, 4, &f)) {
            fprintf(stderr, "FAIL: a network pinning no anchors accepted a table\n");
            return 1; }
    }

    printf("cfanchors ok: a table agreeing with this release and reaching past it is\n"
           "  adopted from the first new height, one disagreement at a pinned height\n"
           "  kills all of it, no shared height is refused, a pin below the floor is\n"
           "  ignored rather than adopted, and the wire form checks tag, version,\n"
           "  reserved bytes, network, count, length and ordering\n");
    return 0;
}
