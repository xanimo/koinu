/* koinu.dog - validator pool tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Real headers through the pool: genesis, which proves its own work, and the three
 * merged-mining proofs from test_auxpow.c, whose work is in their parents. Then the
 * cases that matter more than the happy path: a bad header has to be caught whatever
 * else is in flight, a run of bad headers arriving in height order has to report the
 * lowest of them however the workers divide the run up, and a queue smaller than the
 * work has to block the producer rather than grow.
 *
 * scrypt is the slow part, so this stays under a few hundred headers. */

#include "powq.h"
#include "hex.h"
#include "pow.h"
#include "scrypt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail;

static void bad(const char *what)
{
    fprintf(stderr, "FAIL: %s\n", what);
    fail = 1;
}

/* Dogecoin's genesis header, which meets its own 1e0ffff0 target */
static const char GENESIS[] =
    "010000000000000000000000000000000000000000000000000000000000000000"
    "000000696ad20e2dd4365c7459b4a4a5af743d5e92c6da3229e6532cd605f6533f"
    "2a5b24a6a152f0ff0f1e67860100";

/* block 371337, header then AuxPoW blob, from test_auxpow.c */
static const char AUXPOW[] =
    "020162000d6f03470d329026cd1fc720c0609cd378ca8691a117bd1aa46f01fb09b1a846"
    "8a15bf6f0b0e83f2e5036684169eafb9406468d4f075c999fb5b2a78fbb827ee41fb1154"
    "8441361b0000000001000000010000000000000000000000000000000000000000000000"
    "000000000000000000ffffffff380345bf09fabe6d6d980ba42120410de0554d42a5b5ee"
    "58167bcd86bf7591f429005f24da45fb51cf0800000000000000cdb1f1ff0e000000ffff"
    "ffff01800c0c2a010000001976a914aa3750aa18b8a0f3f0590731e1fab934856680cf88"
    "ac00000000b3e64e02fff596209c498f1b18f798d62f216f11c8462bf39223190000000000"
    "03a979a636db2450363972d211aee67b71387a3daaa3051be0fd260c5acd4739cd52a418d"
    "29d8a0e56c8714c95a0dc24e1c9624480ec497fe2441941f3fee8f9481a3370c334178415"
    "c83d1d0c2deeec727c2330617a47691fc5e79203669312d100000000036fa40307b3a4395"
    "38195245b0de56a2c1db6ba3a64f8bdd2071d00bc48c841b5e77b98e5c7d6f06f92dec5cf"
    "6d61277ecb9a0342406f49f34c51ee8ce4abd678038129485de14238bd1ca12cd2de12ff0"
    "e383aee542d90437cd664ce139446a00000000002000000d2ec7dfeb7e8f43fe77aba3368"
    "df95ac2088034420402730ee0492a2084217083411b3fc91033bfdeea339bc11b9efc986e"
    "161c703e07a9045338c165673f09940fb11548b54021b58cc9ae5";

static size_t unhex(const char *hex, uint8_t **out)
{
    size_t n = strlen(hex) / 2;
    *out = (uint8_t *)malloc(n);
    if (!*out || !kw_hex_decode(hex, strlen(hex), *out, n)) { free(*out); *out = NULL; return 0; }
    return n;
}

int main(void)
{
    uint8_t *gen = NULL, *aux = NULL;
    size_t genlen = unhex(GENESIS, &gen), auxlen = unhex(AUXPOW, &aux);
    if (genlen != 80 || auxlen < 160) { bad("fixtures did not decode"); return 1; }

    /* every header good: one legacy and one merged-mined, submitted together so a
       batch holds both kinds */
    {
        kw_powq *q = kw_powq_start(2, 8);
        if (!q) { bad("the pool would not start"); return 1; }
        for (int i = 0; i < 4; i++) {
            if (!kw_powq_submit(q, 1, gen, NULL, 0)) bad("submit genesis");
            if (!kw_powq_submit(q, 371337, aux, aux + 80, auxlen - 80)) bad("submit auxpow");
        }
        uint64_t checked = 0;
        uint32_t at = 0;
        if (!kw_powq_finish(q, &checked, &at))
            { fprintf(stderr, "FAIL: a good chain failed at height %u\n", at); fail = 1; }
        if (checked != 8) { fprintf(stderr, "FAIL: checked %llu of 8\n", (unsigned long long)checked); fail = 1; }
    }

    /* a header whose nBits demands more work than it has must be caught. Genesis
       with the target of a much later block is exactly that: a real header, a real
       target, and no relationship between them. */
    {
        uint8_t hard[80];
        memcpy(hard, gen, 80);
        hard[72] = 0x84; hard[73] = 0x41; hard[74] = 0x36; hard[75] = 0x1b;   /* 1b364184 */

        kw_powq *q = kw_powq_start(2, 8);
        if (!q) { bad("the pool would not start"); return 1; }
        for (int i = 0; i < 3; i++) kw_powq_submit(q, 100 + (uint32_t)i, gen, NULL, 0);
        kw_powq_submit(q, 500, hard, NULL, 0);
        for (int i = 0; i < 3; i++) kw_powq_submit(q, 900 + (uint32_t)i, gen, NULL, 0);

        uint64_t checked = 0;
        uint32_t at = 0;
        if (kw_powq_finish(q, &checked, &at)) bad("a header short of its target passed");
        else if (at != 500) { fprintf(stderr, "FAIL: reported height %u, want 500\n", at); fail = 1; }
    }

    /* Several bad headers, submitted in height order as a chain arrives: the lowest
       must be reported however the workers divide them up. Submitting them out of
       order would not be a fair test, because the first failure stops the pool and a
       lower height offered afterwards is refused rather than checked. That version of
       this test passed here and failed on i386, where a worker takes one job at a
       time instead of eight. */
    {
        uint8_t hard[80];
        memcpy(hard, gen, 80);
        hard[72] = 0x84; hard[73] = 0x41; hard[74] = 0x36; hard[75] = 0x1b;

        kw_powq *q = kw_powq_start(4, 64);
        if (!q) { bad("the pool would not start"); return 1; }
        for (uint32_t h = 42; h <= 7000; h += 1379) kw_powq_submit(q, h, hard, NULL, 0);
        uint32_t at = 0;
        if (kw_powq_finish(q, NULL, &at)) bad("a run of bad headers passed");
        else if (at != 42) { fprintf(stderr, "FAIL: reported %u, want the lowest, 42\n", at); fail = 1; }
    }

    /* a merged-mining proof with the parent's nonce moved proves nothing */
    {
        uint8_t *broken = (uint8_t *)malloc(auxlen);
        memcpy(broken, aux, auxlen);
        broken[auxlen - 4] ^= 1;                     /* the parent header's nonce */

        kw_powq *q = kw_powq_start(1, 8);
        if (!q) { bad("the pool would not start"); return 1; }
        kw_powq_submit(q, 371337, broken, broken + 80, auxlen - 80);
        uint32_t at = 0;
        if (kw_powq_finish(q, NULL, &at)) bad("a tampered parent passed the pool");
        else if (at != 371337) { fprintf(stderr, "FAIL: reported %u, want 371337\n", at); fail = 1; }
        free(broken);
    }

    /* a queue shorter than the work must block the producer, not lose or grow. 200
       submissions through a ring of 8 is 25 times around it. */
    {
        kw_powq *q = kw_powq_start(2, 8);
        if (!q) { bad("the pool would not start"); return 1; }
        int sent = 0;
        for (uint32_t i = 0; i < 200; i++) if (kw_powq_submit(q, i, gen, NULL, 0)) sent++;
        uint64_t checked = 0;
        if (!kw_powq_finish(q, &checked, NULL)) bad("200 good headers failed");
        if (sent != 200) { fprintf(stderr, "FAIL: sent %d of 200\n", sent); fail = 1; }
        if (checked != 200) { fprintf(stderr, "FAIL: checked %llu of 200\n", (unsigned long long)checked); fail = 1; }
    }

    /* a pool nothing was given must still come back clean */
    {
        kw_powq *q = kw_powq_start(1, 8);
        uint64_t checked = 1;
        if (!q || !kw_powq_finish(q, &checked, NULL)) bad("an empty pool failed");
        if (checked != 0) bad("an empty pool checked something");
    }

    free(gen);
    free(aux);
    if (fail) return 1;
    printf("powq ok: genesis and a real merged-mining proof through one batch, a short\n"
           "  header caught at its own height, the lowest bad height reported, a tampered\n"
           "  parent refused, and 200 headers through a ring of 8\n");
    return 0;
}
