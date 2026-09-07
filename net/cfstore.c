/* koinu.dog - on-disk BIP158 filter cache
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "cfstore.h"
#include "cf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char KW_CF_MAGIC[4] = { 'K', 'W', 'F', '1' };

static int wr_varint(FILE *f, uint64_t v)
{
    uint8_t b[9]; size_t n = 0;
    if (v < 0xfd) b[n++] = (uint8_t)v;
    else if (v <= 0xffff) { b[n++] = 0xfd; b[n++] = (uint8_t)v; b[n++] = (uint8_t)(v >> 8); }
    else if (v <= 0xffffffff) { b[n++] = 0xfe; for (int i = 0; i < 4; i++) b[n++] = (uint8_t)(v >> (8 * i)); }
    else { b[n++] = 0xff; for (int i = 0; i < 8; i++) b[n++] = (uint8_t)(v >> (8 * i)); }
    return fwrite(b, 1, n, f) == n;
}

static int rd_varint(FILE *f, uint64_t *out)
{
    int c = fgetc(f);
    if (c == EOF) return 0;
    if (c < 0xfd) { *out = (uint64_t)c; return 1; }
    int n = c == 0xfd ? 2 : c == 0xfe ? 4 : 8;
    uint64_t v = 0;
    for (int i = 0; i < n; i++) { int b = fgetc(f); if (b == EOF) return 0; v |= (uint64_t)b << (8 * i); }
    *out = v;
    return 1;
}

int kw_cfstore_append(const char *path, const uint8_t block_hash[32],
                      const uint8_t *filter, size_t flen)
{
    FILE *f = fopen(path, "ab");
    if (!f) return 0;
    int ok = 1;
    if (ftell(f) == 0) ok = fwrite(KW_CF_MAGIC, 1, 4, f) == 4;   /* new file: tag it */
    if (ok) ok = fwrite(block_hash, 1, 32, f) == 32;
    if (ok) ok = wr_varint(f, flen);
    if (ok && flen) ok = fwrite(filter, 1, flen, f) == flen;
    if (fclose(f) != 0) ok = 0;
    return ok;
}

long kw_cfstore_count(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    char m[4];
    if (fread(m, 1, 4, f) != 4 || memcmp(m, KW_CF_MAGIC, 4) != 0) { fclose(f); return -1; }
    long n = 0;
    for (;;) {
        uint8_t h[32];
        size_t r = fread(h, 1, 32, f);
        if (r == 0) break;
        if (r != 32) { fclose(f); return -1; }
        uint64_t fl;
        if (!rd_varint(f, &fl) || fseek(f, (long)fl, SEEK_CUR) != 0) { fclose(f); return -1; }
        n++;
    }
    fclose(f);
    return n;
}

long kw_cfstore_sync(kw_peer *p, const kw_headerstore *s, const char *path,
                     uint32_t base_height)
{
    long have = kw_cfstore_count(path);
    if (have < 0 || (size_t)have > s->count) return -1;      /* corrupt or ahead of headers */
    if ((size_t)have == s->count) return (long)s->count;

    const size_t CHUNK = 1000;
    for (size_t s0 = (size_t)have; s0 < s->count; s0 += CHUNK) {
        size_t s1 = s0 + CHUNK;
        if (s1 > s->count) s1 = s->count;

        uint8_t body[37];
        size_t bn = kw_msg_getcfilters_build(KW_CF_TYPE_BASIC, base_height + (uint32_t)s0,
                                             s->h[s1 - 1].hash, body, sizeof body);
        if (!bn || !kw_peer_send(p, "getcfilters", body, bn)) return -1;

        for (size_t k = s0; k < s1; k++) {
            char cmd[13]; const uint8_t *pl = NULL; size_t pn = 0;
            int got = 0;
            while (kw_peer_recv(p, cmd, &pl, &pn) == 1) {
                if (!strcmp(cmd, "cfilter")) { got = 1; break; }
                if (!strcmp(cmd, "ping")) kw_peer_send(p, "pong", pl, pn);
            }
            if (!got) return -1;

            uint8_t type, bh[32]; const uint8_t *filt; size_t flen;
            if (!kw_msg_cfilter_parse(pl, pn, &type, bh, &filt, &flen)) return -1;
            if (type != KW_CF_TYPE_BASIC || memcmp(bh, s->h[k].hash, 32) != 0) return -1;
            if (!kw_cfstore_append(path, bh, filt, flen)) return -1;
        }
    }
    return (long)s->count;
}

long kw_cfstore_match(const char *path, const kw_headerstore *s, uint32_t base_height,
                      const kw_gcs_item *items, size_t nitems,
                      uint32_t *heights, size_t cap)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    char m[4];
    if (fread(m, 1, 4, f) != 4 || memcmp(m, KW_CF_MAGIC, 4) != 0) { fclose(f); return -1; }

    uint8_t *buf = NULL; size_t bcap = 0;
    long n = 0; size_t idx = 0;
    for (;;) {
        uint8_t h[32];
        size_t r = fread(h, 1, 32, f);
        if (r == 0) break;
        if (r != 32) { free(buf); fclose(f); return -1; }
        uint64_t fl;
        if (!rd_varint(f, &fl)) { free(buf); fclose(f); return -1; }
        if (fl > bcap) { uint8_t *nb = realloc(buf, (size_t)fl); if (!nb) { free(buf); fclose(f); return -1; } buf = nb; bcap = (size_t)fl; }
        if (fl && fread(buf, 1, (size_t)fl, f) != (size_t)fl) { free(buf); fclose(f); return -1; }

        if (s && (idx >= s->count || memcmp(h, s->h[idx].hash, 32) != 0)) { free(buf); fclose(f); return -1; }
        int mm = nitems ? kw_gcs_match_any(buf, (size_t)fl, h, items, nitems) : 0;
        if (mm < 0) { free(buf); fclose(f); return -1; }
        if (mm == 1 && (size_t)n < cap) heights[n++] = base_height + (uint32_t)idx;
        idx++;
    }
    free(buf);
    fclose(f);
    return n;
}
