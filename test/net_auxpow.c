/* koinu.dog - fetch a block and check its merged-mining proof for real
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Built on demand, not part of make check, because it needs a peer with the
 * mainnet chain. Give it block hashes in display order and it asks for each block,
 * parses the AuxPoW blob out of it, runs the same check the validator will, and
 * prints the header-plus-blob prefix as hex so a real proof can be embedded as a
 * test fixture. The rest of the block is transactions, which the proof does not
 * involve.
 *
 *   make net_auxpow && ./net_auxpow --node HOST HASH...
 */

#include "auxpow.h"
#include "chainparams.h"
#include "headers.h"
#include "hex.h"
#include "peer.h"
#include "pow.h"
#include "scrypt.h"
#include "sha2.h"
#include "spv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void sha256d(const uint8_t *in, size_t len, uint8_t out[32])
{
    uint8_t once[32];
    kw_sha256(in, len, once);
    kw_sha256(once, 32, out);
}

static void show(const char *label, const uint8_t h[32])
{
    char hex[65];
    uint8_t d[32];
    for (int i = 0; i < 32; i++) d[i] = h[31 - i];
    kw_hex_encode(d, 32, hex, sizeof hex);
    printf("%s %s\n", label, hex);
}

int main(int argc, char **argv)
{
    const kw_chainparams *cp = &KW_DOGE_MAINNET;
    const char *node = NULL;
    int port = -1, first = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--node") && i + 1 < argc) node = argv[++i];
        else if (!strcmp(argv[i], "--port") && i + 1 < argc) port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--testnet")) cp = &KW_DOGE_TESTNET;
        else { first = i; break; }
    }
    if (!node || !first) {
        fprintf(stderr, "usage: net_auxpow --node HOST [--port N] BLOCKHASH...\n");
        return 2;
    }
    if (port < 0) port = cp->p2p_port;

    kw_peer p;
    if (!kw_peer_connect(&p, cp, node, port, 20)) { fprintf(stderr, "connect failed\n"); return 1; }
    if (!kw_peer_handshake(&p, 0)) { fprintf(stderr, "handshake failed\n"); kw_peer_close(&p); return 1; }

    void *scratch = malloc(KW_SCRYPT_SCRATCH);
    int rc = 0;

    for (int a = first; a < argc; a++) {
        uint8_t want[32], hash[32];
        if (!kw_hex_decode(argv[a], strlen(argv[a]), want, 32)) {
            fprintf(stderr, "%s: not a block hash\n", argv[a]);
            rc = 1;
            continue;
        }
        for (int i = 0; i < 32; i++) hash[i] = want[31 - i];   /* display to internal */

        const uint8_t *blk = NULL;
        size_t blen = 0;
        if (!kw_spv_get_block(&p, hash, &blk, &blen)) {
            fprintf(stderr, "%s: could not fetch\n", argv[a]);
            rc = 1;
            continue;
        }
        /* get_block checks the header, not the body, so anything reading the proof
           out of it checks the tree itself. */
        if (!kw_block_merkle_ok(blk, blen)) {
            fprintf(stderr, "%s: body does not match its merkle root\n", argv[a]);
            rc = 1;
            continue;
        }
        if (blen < 80) { fprintf(stderr, "%s: short block\n", argv[a]); rc = 1; continue; }

        uint32_t version = (uint32_t)blk[0] | ((uint32_t)blk[1] << 8) |
                           ((uint32_t)blk[2] << 16) | ((uint32_t)blk[3] << 24);
        uint32_t bits = kw_header_bits(blk);
        uint8_t id[32];
        sha256d(blk, 80, id);

        printf("\n%s\n", argv[a]);
        printf("  version   0x%08x  chain id 0x%04x  %s\n", version, version >> 16,
               (version & KW_BLOCK_VERSION_AUXPOW) ? "auxpow" : "legacy");
        printf("  nBits     %08x\n", bits);
        show("  computed ", id);
        if (memcmp(id, hash, 32) != 0) { printf("  the peer returned a different block\n"); rc = 1; continue; }

        if (!(version & KW_BLOCK_VERSION_AUXPOW)) {
            /* a legacy block proves its own work, and carries no blob at all */
            uint8_t pow[32];
            if (!kw_scrypt_pow(blk, pow, scratch)) { rc = 1; continue; }
            printf("  own scrypt work meets its target: %s\n",
                   kw_pow_check(pow, bits) ? "yes" : "NO");
            continue;
        }

        size_t off = 80;
        kw_auxpow ap;
        if (!kw_auxpow_parse(blk, blen, &off, &ap)) {
            printf("  the blob did not parse\n");
            rc = 1;
            continue;
        }
        printf("  blob      %zu bytes, coinbase %zu, script %zu,"
               " chain branch %zu, coinbase branch %zu, slot %d\n",
               off - 80, ap.coinbase_len, ap.script_len, ap.nchain, ap.nmerkle, ap.chain_index);
        show("  parent   ", ap.parent);

        int ok = kw_auxpow_check(&ap, id, bits, KW_AUXPOW_CHAIN_ID, scratch);
        printf("  check     %s\n", ok ? "PASS" : "FAIL");
        if (!ok) rc = 1;

        /* the fixture: the header and the blob, nothing after */
        char *hex = (char *)malloc(off * 2 + 2);
        if (hex) {
            kw_hex_encode(blk, off, hex, off * 2 + 1);
            printf("  fixture   %zu bytes\n%s\n", off, hex);
            free(hex);
        }
    }

    free(scratch);
    kw_peer_close(&p);
    return rc;
}
