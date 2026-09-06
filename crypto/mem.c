/* koinu.dog - secure memory helpers
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "mem.h"

#include <sys/mman.h>

void kw_secure_zero(void *p, size_t n)
{
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) *v++ = 0;
}

int kw_memeq_ct(const void *a, const void *b, size_t n)
{
    const unsigned char *x = (const unsigned char *)a;
    const unsigned char *y = (const unsigned char *)b;
    unsigned char d = 0;
    for (size_t i = 0; i < n; i++) d |= (unsigned char)(x[i] ^ y[i]);
    return d;   /* 0 == equal */
}

int kw_mlock(void *p, size_t n)   { return mlock(p, n); }
int kw_munlock(void *p, size_t n) { return munlock(p, n); }
