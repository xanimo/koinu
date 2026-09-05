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

## vendored

nothing yet. each primitive that lands here will be listed with its upstream,
the commit or version it was taken from, its license, and the test vectors it is
checked against, before anything is built on it.
