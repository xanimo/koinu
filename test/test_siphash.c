/* koinu.dog - SipHash-2-4 tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Reference vectors from the SipHash paper's implementation (vectors_sip64),
 * key = bytes 00..0f, data = 00..(len-1). */

#include "siphash.h"

#include <stdio.h>
#include <stdint.h>

int main(void)
{
    uint8_t key[16];
    for (int i = 0; i < 16; i++) key[i] = (uint8_t)i;
    uint8_t data[8];
    for (int i = 0; i < 8; i++) data[i] = (uint8_t)i;

    struct { size_t len; uint64_t want; } v[] = {
        { 0, 0x726fdb47dd0e0e31ULL },
        { 1, 0x74f839c593dc67fdULL },
        { 8, 0x93f5f5799a932462ULL },
    };
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        uint64_t got = kw_siphash24(key, data, v[i].len);
        if (got != v[i].want) {
            fprintf(stderr, "FAIL: len %zu got %016llx want %016llx\n",
                    v[i].len, (unsigned long long)got, (unsigned long long)v[i].want);
            return 1;
        }
    }
    printf("siphash ok: 3 reference vectors\n");
    return 0;
}
