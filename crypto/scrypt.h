/* koinu.dog - scrypt (RFC 7914), tuned for Dogecoin's proof of work
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Dogecoin's PoW hash is scrypt(N=1024, r=1, p=1) over the 80-byte block
 * header, with the header as both password and salt, taking 32 bytes out. At
 * those parameters the whole of scrypt is one 128KB scratchpad and 4096 calls
 * to Salsa20/8, so that core is where all the time goes.
 *
 * Header validation hashes many independent headers, which is what the batch
 * entry point is for. It currently interleaves only the scratchpad accesses,
 * which measures the same as the single form because the working set is L2
 * resident and there is no latency to hide; the interface exists so a core that
 * interleaves at register width can be dropped in behind it without touching
 * callers. Prefer it for that reason, not for a speedup it does not yet give. */

#ifndef KOINU_SCRYPT_H
#define KOINU_SCRYPT_H

#include <stddef.h>
#include <stdint.h>

/* The general function, for any (n) a power of two and any r, p. (n) is the
   cost parameter N. Needs 128*r*n bytes of scratch, allocated internally.
   Returns 1, or 0 on a bad parameter or an allocation failure. */
int kw_scrypt(const uint8_t *pass, size_t passlen,
              const uint8_t *salt, size_t saltlen,
              uint64_t n, uint32_t r, uint32_t p,
              uint8_t *out, size_t outlen);

/* Dogecoin's PoW hash of an 80-byte header: scrypt(hdr, hdr, 1024, 1, 1, 32).
   (scratch) is 131072 bytes supplied by the caller so a validator loop does not
   allocate per header; NULL to allocate internally. Returns 1/0. */
#define KW_SCRYPT_SCRATCH 131072

int kw_scrypt_pow(const uint8_t header[80], uint8_t out[32], void *scratch);

/* The same for (count) headers at once, (out) holding (count) 32-byte results.
   (scratch) is KW_SCRYPT_SCRATCH * KW_SCRYPT_BATCH bytes, or NULL to allocate.
   (count) may be any size; it is processed KW_SCRYPT_BATCH at a time with the
   remainder handled singly. Returns 1/0. */
#define KW_SCRYPT_BATCH 4

int kw_scrypt_pow_batch(const uint8_t *headers, size_t count,
                        uint8_t *out, void *scratch);

/* Which Salsa20/8 core the build selected: "sse2", "neon" or "portable". */
const char *kw_scrypt_backend(void);

#endif /* KOINU_SCRYPT_H */
