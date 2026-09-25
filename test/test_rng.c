/* koinu.dog - rng and secure-mem sanity
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "rng.h"
#include "mem.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int all_zero(const unsigned char *b, size_t n)
{
    unsigned char acc = 0;
    for (size_t i = 0; i < n; i++) acc |= b[i];
    return acc == 0;
}

/* Bytes this process has locked, summed over every mapping. The only readable
   account of what mlock holds, since mincore reports residency rather than the
   lock. Returns (size_t)-1 when smaps is unavailable. */
static size_t locked_bytes(void)
{
    int fd = open("/proc/self/smaps", O_RDONLY);
    if (fd < 0) return (size_t)-1;

    char buf[8192];
    size_t total = 0, held = 0;
    ssize_t r;
    while ((r = read(fd, buf + held, sizeof buf - held - 1)) > 0) {
        held += (size_t)r;
        buf[held] = '\0';
        char *line = buf, *nl;
        while ((nl = strchr(line, '\n'))) {
            *nl = '\0';
            unsigned long kb;
            if (sscanf(line, "Locked: %lu kB", &kb) == 1) total += (size_t)kb * 1024;
            line = nl + 1;
        }
        held = strlen(line);
        memmove(buf, line, held);
    }
    close(fd);
    return total;
}

/* Two secrets on one page must survive each other's forget. mlock does not
   count locks, so an munlock of the first used to unlock the page under the
   second. Skipped where nothing can be locked at all, which includes every
   sanitized build: asan and tsan intercept mlock and return success without
   locking, so this case is covered by the plain build only. */
static int check_nested_locks(void)
{
    size_t ps = (size_t)sysconf(_SC_PAGESIZE);
    unsigned char *page = NULL;
    if (posix_memalign((void **)&page, ps, ps) != 0 || !page) {
        fprintf(stderr, "FAIL: cannot align a page\n");
        return 0;
    }
    unsigned char *a = page, *b = page + 64;

    size_t base = locked_bytes();
    if (base == (size_t)-1) { printf("  (no smaps, lock nesting unchecked)\n"); free(page); return 1; }

    kw_secure_keep(a, 32);
    if (locked_bytes() <= base) { printf("  (cannot lock, nesting unchecked)\n"); free(page); return 1; }

    kw_secure_keep(b, 32);
    kw_secure_forget(a, 32);
    if (locked_bytes() <= base) {
        fprintf(stderr, "FAIL: forgetting one secret unlocked the page under another\n");
        free(page);
        return 0;
    }

    kw_secure_forget(b, 32);
    if (locked_bytes() != base) {
        fprintf(stderr, "FAIL: the page stayed locked after the last forget\n");
        free(page);
        return 0;
    }
    free(page);
    return 1;
}

/* Past the counter's capacity a page is locked but untracked, and a later secret
   landing on it would take a freed slot and unlock it under the first. So an
   overflowed process must stop unlocking entirely. Runs after the check above
   and never returns: the overflow is remembered for the life of the process. */
static int check_overflow_keeps_locks(void)
{
    size_t ps = (size_t)sysconf(_SC_PAGESIZE), n = 66;
    unsigned char *pages = NULL;
    if (posix_memalign((void **)&pages, ps, n * ps) != 0 || !pages) {
        fprintf(stderr, "FAIL: cannot align %zu pages\n", n);
        return 0;
    }

    size_t base = locked_bytes();
    if (base == (size_t)-1) { free(pages); return 1; }

    for (size_t i = 0; i < n; i++) kw_secure_keep(pages + i * ps, 32);
    size_t held = locked_bytes();
    if (held < base + 64 * ps) {
        for (size_t i = 0; i < n; i++) kw_secure_forget(pages + i * ps, 32);
        printf("  (cannot lock %zu pages, overflow unchecked)\n", n);
        free(pages);
        return 1;
    }

    kw_secure_forget(pages, 32);
    int ok = locked_bytes() >= held;
    if (!ok) fprintf(stderr, "FAIL: an overflowed process released a page it cannot account for\n");
    for (size_t i = 1; i < n; i++) kw_secure_forget(pages + i * ps, 32);
    free(pages);
    return ok;
}

int main(void)
{
    unsigned char a[64], b[64];

    if (!kw_random_bytes(a, sizeof a)) { fprintf(stderr, "FAIL: rng failed\n"); return 1; }
    if (all_zero(a, sizeof a))         { fprintf(stderr, "FAIL: all zero draw\n"); return 1; }
    if (!kw_random_bytes(b, sizeof b)) { fprintf(stderr, "FAIL: rng failed (2)\n"); return 1; }
    if (!memcmp(a, b, sizeof a))       { fprintf(stderr, "FAIL: two draws identical\n"); return 1; }
    if (!kw_random_selftest())         { fprintf(stderr, "FAIL: selftest\n"); return 1; }

    unsigned char s[16];
    memcpy(s, "secretsecret!!!!", 16);
    kw_secure_zero(s, sizeof s);
    if (!all_zero(s, sizeof s))        { fprintf(stderr, "FAIL: secure_zero\n"); return 1; }

    unsigned char x[4] = {1, 2, 3, 4}, y[4] = {1, 2, 3, 4}, z[4] = {1, 2, 3, 5};
    if (kw_memcmp_ct(x, y, 4) != 0)     { fprintf(stderr, "FAIL: ct compare equal\n"); return 1; }
    if (kw_memcmp_ct(x, z, 4) == 0)     { fprintf(stderr, "FAIL: ct compare differ\n"); return 1; }

    if (!check_nested_locks()) return 1;
    if (!check_overflow_keeps_locks()) return 1;

    printf("rng ok: 64-byte draws differ, selftest passed, secure_zero, ct-compare,\n"
           "  nested locks, and no release once the lock table overflows\n");
    return 0;
}
