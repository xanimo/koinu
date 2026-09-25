/* koinu.dog - secure memory helpers
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "mem.h"

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

void kw_secure_zero(void *p, size_t n)
{
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) *v++ = 0;
}

int kw_memcmp_ct(const void *a, const void *b, size_t n)
{
    const unsigned char *x = (const unsigned char *)a;
    const unsigned char *y = (const unsigned char *)b;
    unsigned char d = 0;
    for (size_t i = 0; i < n; i++) d |= (unsigned char)(x[i] ^ y[i]);
    return d;   /* 0 == equal */
}

int kw_mlock(void *p, size_t n)   { return mlock(p, n); }
int kw_munlock(void *p, size_t n) { return munlock(p, n); }

/* mlock works on whole pages and does not count locks, so a plain munlock of one
   secret unlocks every other secret sharing its pages: kw_keystore_open's key
   sits a frame below the caller's seed, and forgetting the key left the seed
   pageable while it was still in use. Count the locks per page and release a
   page only on the last forget. Capacity is for the handful of secrets a wallet
   holds at once. Past it a page is locked but untracked, and a later secret on
   that same page would take a freed slot and unlock it out from under the first,
   so the overflow is remembered and stops this process unlocking at all. */
#define KW_LOCK_PAGES 64

static pthread_mutex_t lock_mu = PTHREAD_MUTEX_INITIALIZER;
static struct { uintptr_t page; unsigned refs; } lock_tab[KW_LOCK_PAGES];
static int lock_overflow;

static size_t page_size(void)
{
    long v = sysconf(_SC_PAGESIZE);
    return v > 0 ? (size_t)v : 4096;
}

void kw_secure_keep(void *p, size_t n)
{
    static int moaned = 0;
    if (!p || n == 0) return;

    size_t ps = page_size();
    uintptr_t first = (uintptr_t)p & ~(uintptr_t)(ps - 1);
    uintptr_t last  = ((uintptr_t)p + n - 1) & ~(uintptr_t)(ps - 1);
    int err = 0;

    pthread_mutex_lock(&lock_mu);
    for (uintptr_t pg = first; pg <= last; pg += ps) {
        int slot = -1;
        for (int i = 0; i < KW_LOCK_PAGES; i++) {
            if (lock_tab[i].refs && lock_tab[i].page == pg) { slot = i; break; }
        }
        if (slot >= 0) { lock_tab[slot].refs++; continue; }
        if (kw_mlock((void *)pg, ps) != 0) { err = errno; continue; }
        for (int i = 0; i < KW_LOCK_PAGES; i++) {
            if (!lock_tab[i].refs) { lock_tab[i].page = pg; lock_tab[i].refs = 1; slot = i; break; }
        }
        if (slot < 0) lock_overflow = 1;
    }
    pthread_mutex_unlock(&lock_mu);

    if (err && !moaned) {
        moaned = 1;
        fprintf(stderr, "kw: cannot lock %zu bytes into ram (%s); secrets may reach swap\n",
                n, strerror(err));
    }
}

void kw_secure_forget(void *p, size_t n)
{
    kw_secure_zero(p, n);
    if (!p || n == 0) return;

    size_t ps = page_size();
    uintptr_t first = (uintptr_t)p & ~(uintptr_t)(ps - 1);
    uintptr_t last  = ((uintptr_t)p + n - 1) & ~(uintptr_t)(ps - 1);

    pthread_mutex_lock(&lock_mu);
    for (uintptr_t pg = first; pg <= last; pg += ps) {
        for (int i = 0; i < KW_LOCK_PAGES; i++) {
            if (!lock_tab[i].refs || lock_tab[i].page != pg) continue;
            if (--lock_tab[i].refs == 0 && !lock_overflow) kw_munlock((void *)pg, ps);
            break;
        }
    }
    pthread_mutex_unlock(&lock_mu);
}
