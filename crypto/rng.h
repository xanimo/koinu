/* koinu.dog - cryptographically secure random bytes
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#ifndef KOINU_RNG_H
#define KOINU_RNG_H

#include <stddef.h>

/* Fill (len) bytes at (out) with CSPRNG output. Returns 1 on success, 0 on
   failure with (out) zeroed, so a caller that ignores the return spends an
   obvious all-zero buffer rather than uninitialised stack.

   The source is getrandom(2) with flags 0, which blocks only until the kernel
   pool is first seeded and never after, so it cannot hand back unseeded output
   the way /dev/urandom can. The device is used only as a fallback on a kernel
   too old to have the syscall, and even then a short read fails closed. */
int kw_random_bytes(void *out, size_t len);

/* Liveness gate, not a statistical test: draws twice and fails if the source is
   stuck (all zero, or two draws identical). Returns 1 if the RNG looks alive.
   Call once at startup and refuse to run on 0. */
int kw_random_selftest(void);

#endif /* KOINU_RNG_H */
