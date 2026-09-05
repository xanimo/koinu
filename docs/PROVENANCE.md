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

## vendored

nothing yet. each primitive that lands here will be listed with its upstream,
the commit or version it was taken from, its license, and the test vectors it is
checked against, before anything is built on it.
