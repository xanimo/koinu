/* koinu.dog - cryptographically secure random bytes
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "rng.h"
#include "mem.h"

#include <errno.h>
#include <stdint.h>

#if defined(__linux__)
#include <sys/random.h>   /* getrandom(2), glibc >= 2.25 */
#endif
#include <fcntl.h>
#include <unistd.h>

/* Only reached on a kernel too old for getrandom(2). Fails closed on any short
   read rather than leaving the tail of (buf) holding stack junk. */
static int urandom_fallback(uint8_t *buf, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    size_t off = 0;
    while (off < len) {
        ssize_t r = read(fd, buf + off, len - off);
        if (r < 0) { if (errno == EINTR) continue; close(fd); return 0; }
        if (r == 0) { close(fd); return 0; }   /* EOF from a random device: refuse */
        off += (size_t)r;
    }
    close(fd);
    return 1;
}

int kw_random_bytes(void *out, size_t len)
{
    uint8_t *buf = (uint8_t *)out;
    size_t off = 0;

#if defined(__linux__)
    while (off < len) {
        /* flags 0: block until the pool is seeded the first time, then never.
           Requests over 256 bytes can return short, hence the loop. */
        ssize_t r = getrandom(buf + off, len - off, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            if (errno == ENOSYS) break;        /* pre-3.17: try the device */
            kw_secure_zero(out, len);
            return 0;
        }
        off += (size_t)r;
    }
    if (off == len) return 1;
#endif

    if (!urandom_fallback(buf + off, len - off)) {
        kw_secure_zero(out, len);
        return 0;
    }
    return 1;
}

int kw_random_selftest(void)
{
    uint8_t a[32], b[32];
    if (!kw_random_bytes(a, sizeof a)) return 0;
    if (!kw_random_bytes(b, sizeof b)) return 0;

    uint8_t zero = 0;
    for (size_t i = 0; i < sizeof a; i++) zero |= a[i];
    if (zero == 0) return 0;                    /* stuck at all-zero */
    if (kw_memeq_ct(a, b, sizeof a) == 0) return 0;  /* two draws identical */
    return 1;
}
