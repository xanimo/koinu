/* koinu.dog - regenerate the block-header anchor table from a header cache
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Built on demand. The anchors in crypto/chainparams.c are what a sync trusts below
 * the last one, so they go stale as the chain grows and the tail they do not cover
 * is the part that has to be checked the slow way. This prints the table for a cache
 * that has been synced to the tip; the filter-header anchors have their own
 * generator in `kw cfcheckpoints`.
 *
 *   make gen_checkpoints && ./gen_checkpoints main.kwh [spacing]
 *
 * Genesis is not in a cache, which holds height 1 onwards, so it comes from
 * chainparams itself. Run against the committed table it reproduces it exactly,
 * which is the check that this agrees with however the table was first made.
 */

#include "chainparams.h"
#include "headers.h"
#include "hex.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: gen_checkpoints FILE.kwh [spacing]\n"); return 2; }
    unsigned long spacing = argc > 2 ? strtoul(argv[2], NULL, 10) : 25000;
    if (!spacing) { fprintf(stderr, "gen_checkpoints: spacing must not be zero\n"); return 2; }

    FILE *f = fopen(argv[1], "rb");
    if (!f) { fprintf(stderr, "gen_checkpoints: cannot open %s\n", argv[1]); return 1; }
    char tag[4];
    if (fread(tag, 1, 4, f) != 4 || memcmp(tag, "KWH2", 4) != 0) {
        fprintf(stderr, "gen_checkpoints: not a KWH2 cache\n");
        return 1;
    }
    if (fseek(f, 0, SEEK_END) != 0) return 1;
    unsigned long have = (unsigned long)((ftell(f) - 4) / KW_HDR_REC);

    printf("static const kw_checkpoint KW_DOGE_MAINNET_CHECKPOINTS[] = {\n");
    printf("    { 0, \"%s\" },\n", KW_DOGE_MAINNET.genesis);

    unsigned long last = 0;
    for (unsigned long h = spacing; h <= have; h += spacing) {
        uint8_t rec[KW_HDR_REC];
        if (fseek(f, (long)(4 + (h - 1) * KW_HDR_REC), SEEK_SET) != 0) return 1;
        if (fread(rec, 1, KW_HDR_REC, f) != KW_HDR_REC) return 1;

        /* the stored hash is internal order; anchors are written the way an explorer
           shows them */
        uint8_t disp[32];
        char hex[65];
        for (int i = 0; i < 32; i++) disp[i] = rec[KW_HEADER_LEN + 31 - i];
        kw_hex_encode(disp, 32, hex, sizeof hex);
        printf("    { %lu, \"%s\" },\n", h, hex);
        last = h;
    }
    printf("};\n");
    fclose(f);

    fprintf(stderr, "cache holds 1..%lu, anchored every %lu to %lu, %lu entries\n",
            have, spacing, last, last / spacing + 1);
    if (have - last >= spacing)
        fprintf(stderr, "note: %lu headers past the last anchor\n", have - last);
    return 0;
}
