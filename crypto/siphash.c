/* koinu.dog - SipHash-2-4
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Written in-tree from the specification (Aumasson & Bernstein, 2012). Two
 * compression rounds per block, four finalization rounds. */

#include "siphash.h"

static uint64_t rotl(uint64_t x, int b) { return (x << b) | (x >> (64 - b)); }

#define SIPROUND                        \
    do {                                \
        v0 += v1; v1 = rotl(v1, 13); v1 ^= v0; v0 = rotl(v0, 32); \
        v2 += v3; v3 = rotl(v3, 16); v3 ^= v2;                    \
        v0 += v3; v3 = rotl(v3, 21); v3 ^= v0;                    \
        v2 += v1; v1 = rotl(v1, 17); v1 ^= v2; v2 = rotl(v2, 32); \
    } while (0)

static uint64_t rd_le64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i);
    return v;
}

uint64_t kw_siphash24(const uint8_t key[16], const uint8_t *data, size_t len)
{
    uint64_t k0 = rd_le64(key), k1 = rd_le64(key + 8);
    uint64_t v0 = k0 ^ 0x736f6d6570736575ULL;
    uint64_t v1 = k1 ^ 0x646f72616e646f6dULL;
    uint64_t v2 = k0 ^ 0x6c7967656e657261ULL;
    uint64_t v3 = k1 ^ 0x7465646279746573ULL;

    size_t blocks = len - (len % 8);
    for (size_t i = 0; i < blocks; i += 8) {
        uint64_t m = rd_le64(data + i);
        v3 ^= m; SIPROUND; SIPROUND; v0 ^= m;
    }

    uint64_t b = (uint64_t)len << 56;
    for (size_t i = 0; i < (len % 8); i++) b |= (uint64_t)data[blocks + i] << (8 * i);
    v3 ^= b; SIPROUND; SIPROUND; v0 ^= b;

    v2 ^= 0xff; SIPROUND; SIPROUND; SIPROUND; SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}
