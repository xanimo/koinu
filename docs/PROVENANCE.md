# provenance

every piece of cryptography in the binary is either a pinned submodule or a
frozen file in crypto/ whose origin is recorded here. the rule is: submodule
what is big and living, vendor what is small and frozen, and write down where
each vendored file came from and at what commit, so the whole crypto surface is
auditable from this tree.

## submodules

    depends/secp256k1   bitcoin-core/secp256k1   v0.8.0
                        6e2c8bc4ecdc6e71dbe7a368f360d8d453ce435d

## written here

    crypto/rng.c   crypto/rng.h    getrandom(2), /dev/urandom fallback, fails closed
    crypto/mem.c   crypto/mem.h    volatile zero, constant-time compare, mlock
    crypto/hex.c   crypto/hex.h    hex encode/decode, the one place the library
                                   and tests share for hex handling
    crypto/tx.c    crypto/tx.h     legacy tx build, sighash_all and p2pkh signing.
                                   test/test_tx.c reproduces a libdogecoin-signed
                                   spend byte-for-byte and verifies the signature
    crypto/sha2.c  crypto/sha2.h   sha-256/512 clean-room from fips 180-4,
                                   checked against the nist known-answer tests in
                                   test/test_sha2.c (empty, "abc", 1e6 x 'a',
                                   streamed, and double-sha256)
    crypto/ripemd160.c             ripemd-160 clean-room from the dobbertin/
    crypto/ripemd160.h             bosselaers/preneel spec, checked against its
                                   published vectors in test/test_ripemd160.c,
                                   plus hash160 against the bitcoin pubkey example
    crypto/hmac.c  crypto/hmac.h   hmac-sha256 and hmac-sha512 (rfc 2104) over the
                                   sha-2 above, checked against the rfc 4231
                                   vectors in test/test_hmac.c
    crypto/pbkdf2.c                pbkdf2-hmac-sha512 and -sha256 (rfc 8018),
    crypto/pbkdf2.h                checked in test/test_pbkdf2.c against a
                                   one-round identity and the canonical bip39
                                   mnemonic-to-seed vector, and in
                                   test/test_scrypt.c against rfc 7914's sha256
                                   vectors
    crypto/scrypt.c                scrypt (rfc 7914) clean-room from the rfc, with
    crypto/scrypt.h                an entry point at dogecoin's n=1024 r=1 p=1 over
                                   an 80-byte header. salsa20/8 written four times,
                                   sse2, neon, scalar, and the eight-at-once avx2
                                   core in crypto/scrypt_avx2.c. checked in
    crypto/scrypt_avx2.c           test/test_scrypt.c against the three rfc 7914
    crypto/scrypt_avx2.h           vectors, against openssl at dogecoin's
                                   parameters, and vector cores against the scalar
                                   one over random headers
    crypto/base58.c                base58 and base58check (double-sha256 checksum),
    crypto/base58.h                checked in test/test_base58.c against bitcoin's
                                   raw vectors and the classic address examples
    crypto/ec.c    crypto/ec.h     thin wrapper over the secp256k1 submodule:
                                   compressed keys, rfc6979 low-s ecdsa, and the
                                   bip32 tweak-adds. checked in test/test_ec.c
                                   against the G/2G vectors and private/public
                                   derivation agreement
    crypto/bip32.c crypto/bip32.h  bip32 hd keys: master from seed, ckdpriv/pub,
                                   neuter, xprv/xpub, path parsing. checked
                                   against bip32 test vector 1 in test_bip32.c
    crypto/bip39.c crypto/bip39.h  bip39 entropy<->mnemonic and mnemonic->seed
                                   over the wordlist below. english/ascii only,
                                   nfkd not applied. checked against the trezor
                                   vectors in test_bip39.c
    crypto/chainparams.c/.h        dogecoin main/test/regtest version bytes and
                                   coin type, from dogecoin core chainparams.cpp
    crypto/address.c/.h            p2pkh/p2sh addresses and wif over base58check,
                                   checked in test_address.c against libdogecoin-
                                   generated wif/address pairs
    crypto/bip44.c crypto/bip44.h  m/44'/coin'/account'/change/index over bip32,
                                   checked to match the equivalent path string
    crypto/chacha20.c/.h           chacha20 clean-room from rfc 8439
    crypto/aead.c  crypto/aead.h   chacha20-poly1305 aead (rfc 8439) composing the
                                   above with the vendored poly1305 below. all
                                   checked in test/test_aead.c against the rfc
                                   8439 keystream, poly1305 and aead vectors
    crypto/kdf.c   crypto/kdf.h    argon2id wrapper over the vendored argon2 below,
                                   checked in test/test_argon2.c against a phc
                                   reference vector
    crypto/keystore.c/.h           encrypted keystore: argon2id-stretched
                                   passphrase, chacha20-poly1305 with the header
                                   as aad, fail-closed open. checked in
                                   test/test_keystore.c for round trip, wrong
                                   passphrase, and tamper rejection

## vendored

    crypto/wordlist_en.h   the official bip39 english wordlist, 2048 words. the
                           array is checked in test/test_bip39.c to reproduce the
                           canonical file byte for byte, sha256
                           2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda.

    crypto/vendor/poly1305-donna/   poly1305, andrew moon's poly1305-donna,
                           commit e6ad6e091d30d7f4ec2d4f978be1fcfcbce72781,
                           public domain (mit/unlicense per its readme). the
                           130-bit field arithmetic is the error-prone part we
                           do not hand-roll. exercised by the rfc 8439 poly1305
                           and aead vectors in test/test_aead.c.

    crypto/vendor/argon2/  the argon2 reference (p-h-c/phc-winner-argon2), tag
                           20190702, commit 62358ba2123abd17fccf2a108a301d4b52c01a7c,
                           dual cc0-1.0 / apache-2.0 (see its LICENSE). the ref
                           (non-simd) fill and bundled blake2b, built single-
                           threaded (-DARGON2_NO_THREADS). argon2 is complex and
                           consensus-free, exactly the kind to vendor rather than
                           roll. checked against a phc argon2id vector in
                           test/test_argon2.c.

each further primitive that lands here will be listed the same way: its upstream,
the commit or version it came from, its license, and the vectors it is checked
against, before anything is built on it.
