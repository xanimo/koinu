/* koinu.dog - block headers, getheaders/headers, and the header chain
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * The block hash that links the chain is SHA256d of the 80-byte header, not the
 * scrypt PoW hash. AuxPoW-carrying headers (the merged-mining case) are not yet
 * parsed; kw_msg_headers_parse returns -1 on one. Regtest and pre-AuxPoW headers
 * parse fine. */

#ifndef KOINU_HEADERS_H
#define KOINU_HEADERS_H

#include <stddef.h>
#include <stdint.h>

#define KW_HEADER_LEN            80
#define KW_BLOCK_VERSION_AUXPOW  0x100
#define KW_MAX_HEADERS           2000   /* a headers message carries at most this */

typedef struct {
    uint8_t raw[KW_HEADER_LEN];
    uint8_t hash[32];               /* sha256d(raw), internal byte order */
} kw_block_header;

/* Parse the 80-byte header at (in) and compute its hash. Returns 1, or 0 if
   fewer than 80 bytes are available. */
int kw_block_header_parse(const uint8_t *in, size_t len, kw_block_header *h);

/* The previous-block hash field (32 bytes, internal order) and the version. */
const uint8_t *kw_block_header_prev(const kw_block_header *h);
uint32_t       kw_block_header_version(const kw_block_header *h);

/* Build a getheaders payload: version, a varint locator count, the locator
   hashes (internal order), and hash_stop. Returns length or 0. */
size_t kw_msg_getheaders_build(uint32_t version,
                               const uint8_t (*locators)[32], size_t nloc,
                               const uint8_t hash_stop[32],
                               uint8_t *out, size_t outcap);

/* Parse a headers payload into (out). Sets *nout. Returns 1 on success, 0 if
   malformed or the count exceeds (maxout), -1 if any entry carries AuxPoW. */
int kw_msg_headers_parse(const uint8_t *in, size_t len,
                         kw_block_header *out, size_t maxout, size_t *nout);

/* An append-only header chain: each header must link to the current tip. */
typedef struct { kw_block_header *h; size_t count, cap; } kw_headerstore;

int  kw_headerstore_init(kw_headerstore *s);
/* Append (h). The first header seeds the chain; each later one must have prev
   equal to the tip's hash. Returns 1 on success, 0 if it does not connect. */
int  kw_headerstore_append(kw_headerstore *s, const kw_block_header *h);
const kw_block_header *kw_headerstore_tip(const kw_headerstore *s);
void kw_headerstore_free(kw_headerstore *s);

#endif /* KOINU_HEADERS_H */
