/* koinu.dog - a host program using names a library must not have taken
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * argon2 and poly1305-donna export initialize, finalize, allocate_memory and
 * copy_block among others. Before those were prefixed this program could not
 * be linked at all: the linker reported four multiple definitions and stopped.
 * A consumer that happened to vendor argon2 itself got no diagnostic and
 * whichever copy came first.
 *
 * Linked against libkoinu-sign.a by test/test_split.sh. It is a link test, so
 * what it computes matters less than that it builds; it seals a keystore anyway
 * to be sure argon2 is actually pulled in rather than dropped as unreferenced. */

#include "keystore.h"

#include <stdio.h>
#include <string.h>

int   initialize(void)                        { return 7; }
void  finalize(void)                          { }
void *allocate_memory(unsigned long n)        { (void)n; return NULL; }
void  copy_block(void *d, const void *s)      { (void)d; (void)s; }
void  free_memory(void *p)                    { (void)p; }

int main(void)
{
    uint8_t seed[64], out[8192], back[64];
    size_t n, blen = 0;

    memset(seed, 0x5a, sizeof seed);
    n = kw_keystore_seal(seed, sizeof seed, "a passphrase", &KW_KEYSTORE_DEFAULT,
                         out, sizeof out);
    if (!n) { fprintf(stderr, "hostnames: seal\n"); return 1; }
    if (!kw_keystore_open(out, n, "a passphrase", back, sizeof back, &blen) ||
        blen != sizeof seed || memcmp(back, seed, sizeof seed) != 0) {
        fprintf(stderr, "hostnames: the keystore did not round trip\n");
        return 1;
    }
    if (initialize() != 7) { fprintf(stderr, "hostnames: initialize is not mine\n"); return 1; }
    finalize();
    printf("hostnames ok: a host keeping initialize, finalize, allocate_memory, "
           "copy_block\n  and free_memory links the signing half and seals a keystore\n");
    return 0;
}
