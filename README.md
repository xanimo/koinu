# dogewallet

a dogecoin wallet in c, built from the crypto up. secp256k1 is the only
submodule; everything else it needs cryptographically lives in crypto/, either
vendored from a named upstream at a named commit or written here, and frozen.

## building

    make check      # builds libdogewallet.a and runs the test
    make asan       # the same under address and undefined-behaviour sanitizers

today that is the rng and the secure-memory helpers. the rng is getrandom(2),
with a /dev/urandom fallback only for a kernel too old for the syscall. it fails
closed: on any error it zeroes the buffer and returns false, so a caller that
ignores the return spends an all-zero key rather than uninitialised stack.

## layout

a library core (libdogewallet.a) with a thin cli on top: the core owns the
crypto, the keys and the wallet state, and the cli stays dumb. docs/PROVENANCE.md
records the secp256k1 pin and where every vendored primitive came from.
