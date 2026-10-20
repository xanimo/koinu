/* koinu.dog - the vendored primitives' symbol names, prefixed
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * argon2, its blake2b and poly1305-donna export names a host program is
 * entitled to use for its own: initialize, finalize, allocate_memory,
 * free_memory, copy_block, encode_string, decode_string. A program that
 * defines any of them cannot link libkoinu-sign.a at all, and one that
 * vendors argon2 itself gets whichever copy the linker reached first with no
 * diagnostic. Either is the library's fault rather than the caller's.
 *
 * Renamed here rather than patched into the vendored sources, so what is in
 * crypto/vendor is still what came from upstream and docs/PROVENANCE.md's
 * hashes still describe it. Force-included into every translation unit by
 * CPPFLAGS, so a definition, a declaration and a call are renamed together.
 *
 * test/test_split.sh links a program defining four of these names and fails
 * if the archive still exports anything outside the kw_ and KW_ prefixes. */

#ifndef KOINU_VENDOR_SYMBOLS_H
#define KOINU_VENDOR_SYMBOLS_H

/* argon2 internals, the names most likely to be a host's own */
#define FLAG_clear_internal_memory kw_vendor_FLAG_clear_internal_memory
#define allocate_memory            kw_vendor_allocate_memory
#define b64len                     kw_vendor_b64len
#define clear_internal_memory      kw_vendor_clear_internal_memory
#define copy_block                 kw_vendor_copy_block
#define decode_string              kw_vendor_decode_string
#define encode_string              kw_vendor_encode_string
#define fill_first_blocks          kw_vendor_fill_first_blocks
#define fill_memory_blocks         kw_vendor_fill_memory_blocks
#define fill_segment               kw_vendor_fill_segment
#define finalize                   kw_vendor_finalize
#define free_memory                kw_vendor_free_memory
#define index_alpha                kw_vendor_index_alpha
#define init_block_value           kw_vendor_init_block_value
#define initial_hash               kw_vendor_initial_hash
#define initialize                 kw_vendor_initialize
#define numlen                     kw_vendor_numlen
#define secure_wipe_memory         kw_vendor_secure_wipe_memory
#define validate_inputs            kw_vendor_validate_inputs
#define xor_block                  kw_vendor_xor_block

/* argon2's public interface */
#define argon2_ctx            kw_vendor_argon2_ctx
#define argon2_encodedlen     kw_vendor_argon2_encodedlen
#define argon2_error_message  kw_vendor_argon2_error_message
#define argon2_hash           kw_vendor_argon2_hash
#define argon2_type2string    kw_vendor_argon2_type2string
#define argon2_verify         kw_vendor_argon2_verify
#define argon2_verify_ctx     kw_vendor_argon2_verify_ctx
#define argon2d_ctx           kw_vendor_argon2d_ctx
#define argon2d_hash_encoded  kw_vendor_argon2d_hash_encoded
#define argon2d_hash_raw      kw_vendor_argon2d_hash_raw
#define argon2d_verify        kw_vendor_argon2d_verify
#define argon2d_verify_ctx    kw_vendor_argon2d_verify_ctx
#define argon2i_ctx           kw_vendor_argon2i_ctx
#define argon2i_hash_encoded  kw_vendor_argon2i_hash_encoded
#define argon2i_hash_raw      kw_vendor_argon2i_hash_raw
#define argon2i_verify        kw_vendor_argon2i_verify
#define argon2i_verify_ctx    kw_vendor_argon2i_verify_ctx
#define argon2id_ctx          kw_vendor_argon2id_ctx
#define argon2id_hash_encoded kw_vendor_argon2id_hash_encoded
#define argon2id_hash_raw     kw_vendor_argon2id_hash_raw
#define argon2id_verify       kw_vendor_argon2id_verify
#define argon2id_verify_ctx   kw_vendor_argon2id_verify_ctx

/* the blake2b argon2 is built on */
#define blake2b            kw_vendor_blake2b
#define blake2b_final      kw_vendor_blake2b_final
#define blake2b_init       kw_vendor_blake2b_init
#define blake2b_init_key   kw_vendor_blake2b_init_key
#define blake2b_init_param kw_vendor_blake2b_init_param
#define blake2b_long       kw_vendor_blake2b_long
#define blake2b_update     kw_vendor_blake2b_update

/* poly1305-donna */
#define poly1305_auth               kw_vendor_poly1305_auth
#define poly1305_finish             kw_vendor_poly1305_finish
#define poly1305_init               kw_vendor_poly1305_init
#define poly1305_power_on_self_test kw_vendor_poly1305_power_on_self_test
#define poly1305_update             kw_vendor_poly1305_update
#define poly1305_verify             kw_vendor_poly1305_verify

#endif /* KOINU_VENDOR_SYMBOLS_H */
