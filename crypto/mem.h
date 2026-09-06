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

#endif /* KOINU_MEM_H */
