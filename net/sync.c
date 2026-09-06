/* koinu.dog - header chain sync driver
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "sync.h"
#include "msg.h"
#include "hex.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int kw_net_verbose = 0;

long kw_sync_headers(kw_peer *p, kw_headerstore *s, const kw_chainparams *cp)
{
    /* genesis hash in internal order, for the initial locator and link check */
    uint8_t genesis[32], disp[32];
    if (!cp || !kw_hex_decode(cp->genesis, 64, disp, 32)) return -1;
    for (int i = 0; i < 32; i++) genesis[i] = disp[31 - i];

    kw_block_header *batch = (kw_block_header *)malloc(KW_MAX_HEADERS * sizeof *batch);
    if (!batch) return -1;

    long total = 0;
    for (;;) {
        const kw_block_header *tip = kw_headerstore_tip(s);
        uint8_t loc[32];
        if (tip) memcpy(loc, tip->hash, 32);
        else     memcpy(loc, genesis, 32);

        uint8_t body[128];
        size_t bn = kw_msg_getheaders_build(KW_PROTOCOL_VERSION,
                                            (const uint8_t (*)[32])loc, 1, NULL,
                                            body, sizeof body);
        if (!bn || !kw_peer_send(p, "getheaders", body, bn)) { free(batch); return -1; }

        /* read past anything that is not a headers message, answering pings */
        char cmd[13]; const uint8_t *pl = NULL; size_t pn = 0;
        int got = 0, r;
        while ((r = kw_peer_recv(p, cmd, &pl, &pn)) == 1) {
            if (!strcmp(cmd, "headers")) { got = 1; break; }
            if (!strcmp(cmd, "ping")) kw_peer_send(p, "pong", pl, pn);
        }
        if (!got) { free(batch); return -1; }

        size_t nout = 0;
        if (kw_msg_headers_parse(pl, pn, batch, KW_MAX_HEADERS, &nout) != 1) { free(batch); return -1; }
        if (nout == 0) break;                    /* peer has nothing after our tip */

        /* seeding from empty: the first header must build on genesis */
        if (!kw_headerstore_tip(s) &&
            memcmp(kw_block_header_prev(&batch[0]), genesis, 32) != 0) { free(batch); return -1; }

        for (size_t i = 0; i < nout; i++) {
            if (!kw_headerstore_append(s, &batch[i])) { free(batch); return -1; }
            total++;
        }
        if (kw_net_verbose) fprintf(stderr, "[headers] %ld synced\n", total);
    }

    free(batch);
    return total;
}
