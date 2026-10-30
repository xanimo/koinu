# ABI

What a program linked against `libkoinu-sign.so.0` or `libkoinu-chain.so.0` can
rely on, and what it cannot. `test/test_abi.sh` checks the mechanical half of
this on every `make check`.

## The soname is not the version

`KW_ABI` in the Makefile is the soname number and the release version is
`KW_VERSION` in `include/kw_version.h`. They move independently:
`libkoinu-sign.so.0.2.5` and `libkoinu-sign.so.0.4.0` both carry soname
`libkoinu-sign.so.0`, and a program linked against either keeps running against
the other.

It is 1 as of 0.5.0. `kw_psbt_sign` now refuses a p2sh redeem script that does
not name the signing key, which is the "narrowing what a function accepts" entry
below: binding the script to the coin says the script is the one the coin is
locked to and says nothing about whose signature it wants, so a caller handed a
script naming somebody else got a signature and a success. A caller that relied
on that now gets a refusal it cannot tell from a bug, which is why that entry is
on the list. `libkoinu-sign.so.0` and `.so.1` install side by side.

## The exported set

Every exported name begins with `kw_` or `KW_`, and nothing else is exported at
all. The library is built with a version script, so the vendored code and the
pinned secp256k1 are inside it without being on its dynamic symbol table: a
program that links its own libsecp256k1 gets its own, not koinu's, which is the
whole reason koinu does not install one.

That means `dlopen` on either half works with no other koinu library present,
and `nm -D --defined-only` on it is the complete list of what this document
covers. A name not on that list is not part of the ABI however it is spelled.

## The types a caller holds

`kw_tx`, `kw_psbt`, `kw_utxoset`, `kw_watchset` and `kw_journal` are opaque.
Their contents, their sizes and the number of fields in them change without
notice and without a soname bump, because a caller cannot observe any of it: the
only way to make one is `kw_tx_new` and friends, and the only way to read one is
an accessor. `crypto/tx_internal.h`, `crypto/psbt_internal.h`,
`wallet/utxo_internal.h` and `wallet/journal_internal.h` carry those layouts for
this project's own code and are not installed.

These are records, and their layout is frozen for the life of a soname:

    kw_bip32_version    the two four-byte prefixes of a network
    kw_bip32_key        an extended key, whose shape BIP32 fixes
    kw_chainparams      a network's constants
    kw_keystore_params  the kdf cost a seal is written with
    kw_slip39_group     a member threshold and a member count
    kw_slip39_share     one decoded share
    kw_codex32          one decoded codex32 string
    kw_journal_entry    one line of the journal
    kw_utxo             one tracked output
    kw_utxo_watcher     three function pointers and a context
    kw_sha256_ctx       a streaming hash state
    kw_sha512_ctx       the same for sha512

A caller declares those by value, copies them, and puts them in its own structs.
`kw_utxo_watcher` is on the list because a caller fills one in; adding a fourth
callback to it changes its size and is a bump.

The `KW_*` constants that appear in those layouts (`KW_SPK_MAX`,
`KW_TX_SCRIPT_MAX`, and the rest) are part of them. Changing one changes the
size of a struct a caller has already compiled in, so it is a bump even though
the field names stay the same.

## What bumps the soname

- Removing an exported function, or changing its parameters or return type.
- Changing the layout of anything in the list above, including through a `KW_*`
  constant it uses.
- Inserting an enumerator anywhere but the end of `kw_slip39_err`,
  `kw_codex32_err`, `kw_utxoset_err`, or `kw_log_level`, which would renumber
  the ones after it.
- Narrowing what a function accepts, or making it refuse an input it used to
  take. A caller cannot see the difference between that and a bug, but it breaks
  the same way.

## What does not

- Adding an exported function. `kw_script_cosignable` arrived this way in 0.5.0:
  it answers whether a script names a key and still needs somebody else, which is
  the question a co-signer asks and a plain signer does not. The checks it makes
  were in the cli until then, so a caller linking the library could sign a 1-of-2
  the cli would refuse.
- Adding an enumerator at the end of one of those enums. A caller that switches
  over one and has no `default:` will stop covering every case, which is a
  warning in its build and not a break in ours.
- Anything inside an opaque type.
- Changing which bytes a function writes to a buffer it was handed, where the
  format is the chain's rather than this project's. A transaction serializer
  that starts emitting a different encoding is a consensus change, not an ABI
  change, and would be refused on other grounds.

## What is not promised at all

Nothing about the static archives' internal symbols, which are whatever the
source happens to define. Nothing about `kw_vendor_*`: those exist so two copies
of argon2 or poly1305 in one process do not collide, and the prefixing is an
implementation detail that can change with the vendored code.

Nothing about thread safety beyond what a function's own comment says. The
library has no global state a caller can reach, with two exceptions that are
process-wide by nature: `kw_log_set` installs one sink for the process, and
`kw_ec_start`/`kw_ec_stop` bracket secp256k1's context. Both are meant to be
called once, from one thread, before and after everything else.

## Not done

macOS. `ld64` wants `.dylib`, `-install_name` and `-exported_symbols_list`, and
none of that is written. The Makefile probes for `--version-script` and
`-soname` by linking a real shared object with each, and where either is missing
`make shared` says so and builds nothing, `make install` places the archives
alone, and `test/test_abi.sh` skips. There is no Darwin shared library, rather
than an untested one.

The probe is on the linker and not on the platform or on which tools are
installed, which is the distinction that matters: the macos runner has a
`readelf`, so skipping on that was skipping nothing, and the build failed in the
middle of the link.

No pkg-config variable says which of the two linkages a consumer got. `-lkoinu-sign`
takes the shared library where both are present, which is the usual rule, and a
consumer that wants the archive asks for it by path.
