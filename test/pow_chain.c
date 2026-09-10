/* koinu.dog - check the retarget rule against a real header chain
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Built on demand, not part of make check, because it wants a KWH2 header cache
 * that nothing in the tree ships: 112 bytes a header, 700MB for mainnet. Run it
 * over one and every height's nBits is recomputed from the two timestamps the rule
 * asks for and compared to what the header actually carries. A mainnet cache is
 * six million independent checks of the rule, including both regime switches.
 *
 *   make pow_chain && ./pow_chain main.kwh [limit]
 */

#include "pow.h"
#include "headers.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* genesis is not in the store: the cache holds height 1 onwards */
#define GENESIS_TIME 1386325540u
#define GENESIS_BITS 0x1e0ffff0u

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: pow_chain FILE.kwh [limit]\n"); return 2; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { fprintf(stderr, "pow_chain: cannot open %s\n", argv[1]); return 1; }

    char tag[4];
    if (fread(tag, 1, 4, f) != 4 || memcmp(tag, "KWH2", 4) != 0) {
        fprintf(stderr, "pow_chain: not a KWH2 cache\n");
        fclose(f);
        return 1;
    }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 1; }
    long size = ftell(f);
    unsigned long have = (unsigned long)((size - 4) / KW_HDR_REC);
    unsigned long limit = argc > 2 ? strtoul(argv[2], NULL, 10) : have;
    if (limit > have) limit = have;
    printf("%s holds heights 1..%lu, checking to %lu\n", argv[1], have, limit);

    /* one pass, holding only what the rule needs: every timestamp, because a
       retarget names an arbitrary earlier height */
    uint32_t *times = (uint32_t *)malloc((limit + 1) * sizeof *times);
    uint32_t *bits  = (uint32_t *)malloc((limit + 1) * sizeof *bits);
    if (!times || !bits) { fprintf(stderr, "pow_chain: out of memory\n"); return 1; }
    times[0] = GENESIS_TIME;
    bits[0]  = GENESIS_BITS;

    if (fseek(f, 4, SEEK_SET) != 0) { fclose(f); return 1; }
    for (unsigned long h = 1; h <= limit; h++) {
        uint8_t rec[KW_HDR_REC];
        if (fread(rec, 1, KW_HDR_REC, f) != KW_HDR_REC) {
            fprintf(stderr, "pow_chain: short read at height %lu\n", h);
            return 1;
        }
        times[h] = kw_header_time(rec);
        bits[h]  = kw_header_bits(rec);
    }
    fclose(f);

    unsigned long checked = 0, retargets = 0, bad = 0;
    for (unsigned long h = 1; h <= limit; h++) {
        uint32_t first_h = 0;
        int rt = kw_pow_retargets(&KW_POW_MAIN, (uint32_t)h, &first_h);
        if (rt && first_h > h - 1) { fprintf(stderr, "pow_chain: %lu asked for a future block\n", h); return 1; }
        uint32_t want = kw_pow_next_bits(&KW_POW_MAIN, (uint32_t)h, bits[h - 1],
                                         times[h - 1], rt ? times[first_h] : 0);
        checked++;
        if (rt) retargets++;
        if (want != bits[h]) {
            if (bad < 20)
                fprintf(stderr, "MISMATCH height %lu: header %08x, rule %08x "
                                "(retarget %d, first %u, last_time %u, first_time %u)\n",
                        h, bits[h], want, rt, first_h, times[h - 1],
                        rt ? times[first_h] : 0);
            bad++;
        }
    }

    free(times);
    free(bits);
    printf("%lu heights checked, %lu of them retargets, %lu mismatches\n",
           checked, retargets, bad);
    return bad ? 1 : 0;
}
