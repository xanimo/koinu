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

/* memcmp semantics in constant time: 0 when equal, nonzero when not. Named for
   memcmp rather than for equality so the sense cannot be read backwards. */
int kw_memcmp_ct(const void *a, const void *b, size_t n);

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
   bytes are gone before the page can be paged out again.

   They nest by page, so two secrets sharing a page survive each other's forget.
   Passing a range that was never kept is allowed and unlocks nothing. A process
   that holds secrets on more pages than the counter tracks keeps every lock for
   the rest of its life rather than risk releasing one it cannot account for. */
void kw_secure_keep(void *p, size_t n);
void kw_secure_forget(void *p, size_t n);

/* Stop this process dumping core, and ask the kernel to leave locked pages out
   of a dump where it can. mlock keeps a secret out of swap and does nothing
   about a core file: a SIGQUIT at a passphrase prompt wrote a mnemonic the user
   had not read yet into one, under systemd-coredump or apport or a ci artifact
   collector. Called from main before anything reads a secret. Best effort, like
   the locking: a platform without it is no reason to refuse to run. */
void kw_no_core_dumps(void);

/* Write (n) bytes to (fd) without stdio in between. printf copies a secret into
   a buffer malloc'd on first use, which nothing wipes and which outlives every
   kw_secure_forget in the process; read_secret avoids stdio on the way in for
   the same reason. Returns 1 when every byte was written. */
int kw_write_secret(int fd, const void *p, size_t n);

#endif /* KOINU_MEM_H */
