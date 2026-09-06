# koinu

a dogecoin wallet in c, built from the crypto up. secp256k1 is the only
submodule; everything else it needs cryptographically lives in crypto/, either
vendored from a named upstream at a named commit or written here, and frozen.

## building

    make check      # builds libkw.a and runs the test
    make asan       # the same under address and undefined-behaviour sanitizers

today that is the rng and the secure-memory helpers. the rng is getrandom(2),
with a /dev/urandom fallback only for a kernel too old for the syscall. it fails
closed: on any error it zeroes the buffer and returns false, so a caller that
ignores the return spends an all-zero key rather than uninitialised stack.

## layout

a library core (libkw.a) with a thin cli on top: the core owns the
crypto, the keys and the wallet state, and the cli stays dumb. docs/PROVENANCE.md
records the secp256k1 pin and where every vendored primitive came from.

## kw

the cli. the keystore holds the seed; the mnemonic is printed once and never
stored, so it is the only backup.

    kw new     --keystore w.ks               generate, seal, show the mnemonic
    kw restore --keystore w.ks --mnemonic -  seal an existing mnemonic
    kw address --keystore w.ks               derive m/44'/coin'/0'/0/index

passphrases and mnemonics are read from a file (@path), stdin (-), or a no-echo
prompt, never from argv. --testnet and --regtest switch networks.
