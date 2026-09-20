/* koinu.dog - secure memory helpers
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#ifndef KOINU_MEM_H
#define KOINU_MEM_H

#include <stddef.h>

/* Zero (n) bytes at (p) through a volatile pointer so the write survives the
   optimizer even when the buffer is about to be freed or leave scope. Use it on
   anything that held key material. */
void kw_secure_zero(void *p, size_t n);

/* Compare (n) bytes without short-circuiting: returns 0 if equal, nonzero
   otherwise, and takes the same time whether they differ in the first byte or
   the last, so it leaks nothing about a secret through timing. */
int kw_memeq_ct(const void *a, const void *b, size_t n);

/* Best-effort pin of (n) bytes at (p) into RAM so secrets are not paged to
   swap, and the matching release. Return 0 on success. A failure is not fatal
   by itself but means the pages may reach disk, so a caller holding keys should
   surface it rather than ignore it. */
int kw_mlock(void *p, size_t n);
int kw_munlock(void *p, size_t n);

/* Hold (p,n) in RAM while it holds a secret, and give it up once wiped. These
   exist because kw_mlock had no callers anywhere in the tree while the threat
   model said the seed was mlock'd: a stack buffer holding 64 bytes of seed is
   pageable, and a machine with swap can write it to disk in the clear where it
   survives a reboot. That is not the compromised host the threat model excludes,
   because nobody has to be present when it happens.

   Best effort on purpose. A container with RLIMIT_MEMLOCK at zero would
   otherwise make the wallet refuse to start, so a failure says so once and
   carries on. kw_secure_forget zeroes before it unlocks, in that order, so the
   bytes are gone before the page can be paged out again. */
void kw_secure_keep(void *p, size_t n);
void kw_secure_forget(void *p, size_t n);

#endif /* KOINU_MEM_H */
