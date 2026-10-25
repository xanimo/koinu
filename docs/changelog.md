# Changelog

## [Unreleased]

## What's Changed
* kw send: broadcast to every --node given, not just the last
  --node has been repeatable for the header sync since 0.3.0, and send quietly
  used only the last one. A transaction reaches the network through whichever
  peer relays it first, so one unlucky or unreachable peer was the whole
  broadcast; and a wallet that tells exactly one node what it is spending has
  also told that node who is spending it. With --tor, which send already
  supported, several peers is the difference between one party knowing and none.

  The per-peer probe is unchanged, lifted whole into send_to_peer rather than
  rewritten: it was tuned against a real node, down to the inventory timer
  being a poisson draw averaging five seconds. One peer holding it is a
  broadcast, and a reject from any peer outranks silence from the rest. Output
  for a single --node is byte for byte what it was.
* kw cfcheck: hold a filter source to the anchors, and to a second source
  The serving half is only worth having if a client can judge what it gets.
  `kw cfcheck --daemon SOCK [--daemon SOCK2] --since H` reads a filter-header
  chain off a kwd socket, checks every compiled-in anchor the range covers, and
  where two sockets are given, checks the two against each other. A chain that
  contradicts an anchor is refused. A single source that matches every anchor is
  still one source above the last one, and it says so in the same words koinu
  already uses for chain work rather than implying agreement it did not get.

  The source it is driven by is test/cfstub rather than nc: the reply has to be
  exact, including shapes a real kwd would never send, and nc can bind a unix
  socket on linux and not on macos, where the gate failed for a reason that had
  nothing to do with the code under test.

  The read now carries a 20 second receive timeout. It ends at EOF, so without
  one a source that answers and never closes held the wallet forever, and a
  filter source is someone else's machine.
* kwd: serve the filters themselves, streamed rather than buffered
  `cffilters <from> <count>` completes the pair: cfheaders says what the chain
  commits to and this hands over the bytes it commits to, so a client can take
  filters from one node and check them against a chain from another. Bounded at
  500 a reply rather than 2000, since each line is a filter and not 32 bytes.

  kw_cfstore_each walks the cache from a height, seeking there through the
  index rather than from the base, and hands each filter to a callback. Nothing
  buffers a range: kwd hex-encodes straight to the socket two characters at a
  time and stops at the first short write, so a client that hangs up costs one
  filter rather than the whole span. The count line is settled against what is
  actually cached before any filter is written, because a reply promising n and
  delivering fewer is indistinguishable from a truncated connection.
* kwd: serve the filter-header chain, so a filter source can be checked
  A light client that takes BIP158 filters from one place has no way to tell a
  missing entry from an empty block, and the filter it needs is the same filter
  every other wallet needs. So kwd hands out the chain it has already verified:
  `cfheaders <from> <count>` returns one filter header per height, bounded at
  2000 a reply, from the sidecar's verified base rather than anything the
  process invents. Nothing in it is private, and the asker names a height range
  instead of an address, which is the whole difference from BIP37.

  kw_cfstore_headers recomputes the chain from the kept filters on each call
  rather than storing a second copy, and kw_cfstore_base reads the verified
  base. The test checks the chain is really BIP157's by rebuilding it from the
  vectors the other way, header(i) = step(hash256(filter_i), header(i-1)),
  since a chain that is merely self-consistent would pass any check derived
  from itself.

  This is the first half of filters without waiting for Core to serve them: a
  node that has them can pass them on, and because the receiver chains what it
  gets to a compiled-in anchor, a server that lies is caught rather than
  trusted.
* test: a gate that cannot answer is not a gate that passes
  test_abi.sh asked the Makefile whether a shared library builds here by
  running a third make, and under make asan that query came back empty. The
  script read "not the string yes" as "this linker cannot", skipped itself, and
  the run still reported success: asan covered 47 of 48 suites while saying it
  covered all of them, so the .so was never once exercised under the
  sanitizers. The answer is passed in from the Makefile now, which already
  knows it, and the query that remains for standalone use distinguishes yes
  from no from a failure, stopping the run on the third rather than guessing.
  make asan goes from 41 ok lines to 51 and reports abi ok.

## [0.4.0] - 2026-10-23

## Upgrading

Rescan. The utxo set is v2 and carries the transaction behind every output, so a
v1 file does not load and `kw sign`, `kw sweep` and `kwui` report the version
rather than a balance until `kw scan` or `kw sweep --watch` writes a new one.
Nothing is lost by it: the set is derived from the chain.

What a caller has to change:

- `kw_utxoset_add` takes the raw transaction that created the output, or NULL
  for an entry that only has to work in memory. `kw_utxoset_save` refuses a set
  holding one of those.
- `kw_utxoset_load` takes a `kw_utxoset_err *`, which may be NULL, so a caller
  can tell "no file, run a scan" from "this file names an amount its own
  transaction does not carry".
- A test or script that wrote a utxo set by hand cannot any more. `test/mkutxos`
  builds one through the same path a scan uses.

`kw sweep` is two commands. A single run that took `--wif` and `--node` together
held the key in the process that opened the socket, so the networked half and
the signing half are separate invocations now:

    kw sweep --watch ADDR --utxos F --node HOST   finds the coins, reads no key
    kw sweep --wif @FILE --to ADDR --utxos F      signs them, opens no socket
    kw send  --tx @FILE --node HOST               broadcasts

Passing `--watch` and `--wif` in one run is refused. A caller doing the old
one-shot form has to split it and pass `--utxos`.

`kw_tx`, `kw_psbt`, `kw_utxoset`, `kw_watchset` and `kw_journal` are opaque.
Each `kw_x y; kw_x_init(&y);` becomes `kw_x *y = kw_x_new();` with a matching
free, and a field read becomes an accessor: `kw_tx_nin`, `kw_tx_nout`,
`kw_tx_output`, `kw_tx_input_prevout`, `kw_tx_input_script`,
`kw_utxoset_count`, `kw_utxoset_at`, `kw_watchset_count`, `kw_watchset_seen`,
`kw_journal_count` and `kw_journal_at`. Build with
`-Werror=incompatible-pointer-types`: a `&y` left behind compiles and signs the
wrong bytes. docs/abi.md says which types a soname freezes and which it does
not.

## What's Changed
* chainparams: anchor 6425000
  The chain passed the next 25000-height anchor, so the tail a sync has to check
  the slow way had grown to 26751 headers. gen_checkpoints reproduces all 257
  committed entries exactly and adds this one. The filter anchors sit every
  100000 and the last is 6400000, which the tip at 6426751 has not passed, so
  that table is unchanged.
* build: libkoinu-sign.so.0 and libkoinu-chain.so.0, with docs/abi.md
  The soname was waiting on the handles, and they are done, so there is a
  shared library and a written promise. kw_tx, kw_psbt, kw_utxoset, kw_watchset
  and kw_journal are handles whose contents move freely; the dozen records a
  caller declares by value, and the KW_* constants their layouts use, are
  frozen for the life of a soname. KW_ABI is separate from KW_VERSION, so 0.4.1
  and 0.5.0 both carry soname 0.

  A version script pins the exported set to kw_ and KW_, which is what makes
  the promise checkable: the pinned secp256k1 is linked in without being
  re-exported, so a program that brings its own gets its own rather than
  whichever the loader reached first. The submodule is configured --with-pic
  now, since a non-PIC archive cannot go into a .so at all.

  test/test_abi.sh reads all of it back off the built library: the soname, the
  symlink chain, the exported set, that secp256k1 is present and local, and
  that a dynamically linked consumer runs. Removing the version script makes it
  report secp256k1_context_create; removing -soname makes it report an empty
  soname.

  Both flags are probed by linking a real shared object with each, and where
  either is missing there is no shared library at all: make shared says so,
  install places the archives alone, and the test skips. That is the macos case,
  which wants .dylib and -install_name and is not written.
* build: a second install with a different PREFIX wrote the first one's .pc
  The generated .pc depends on PREFIX, which is not an input make can see, so
  the file was up to date whatever the prefix was: `make install PREFIX=/opt/a`
  then `make install PREFIX=/usr` installed a .pc still naming /opt/a, and
  pkg-config pointed a consumer at headers that were not there. The prefix goes
  through a stamp file now, so changing it rebuilds the .pc.
* build: make check compiles and replays the fuzz harnesses
  Nothing in the fast loop built them, and the libFuzzer ones want a compiler
  the gate does not require, so a header change that broke fuzz_parse and two
  netfuzz targets reached a push twice: only make fuzz-asan compiles them, and
  it is the slowest thing in the release gate. check ends with fuzz-run, which
  builds the replay harness with the ordinary compiler and runs the corpus
  through it, and fuzz-syntax, which is -fsyntax-only over the eight netfuzz
  targets and the two wire harnesses. Reintroducing the &handle that started
  this fails fuzz-syntax.
* utxo, journal: the watch set and the journal are opaque too
  Both were a pointer to a library-owned array and its two sizes, declared by
  value on a caller's frame, so a lookup this walks linearly is one no later
  version can index without breaking every caller. kw_watchset_new and
  kw_journal_new replace the init pair; kw_watchset_count/_seen and
  kw_journal_count/_at cover what a caller read. kw_watch is internal, and
  kw_journal_entry stays public since a caller writes one and reads it back.

  This is the last of them: what the installed headers still spell out are
  records a caller legitimately holds, which is what an abi promise can name.
* build: the hand-run diagnostics are built by the gate
  net_cf had assigned a global deleted five commits earlier and fz_kwdflow the
  same, because nothing compiled either: each needs a live peer, so they are
  built on demand and the demand came after the change. make tools builds the
  twelve of them without running any, and CI runs it on both compilers and on
  32-bit. make fuzz-net was already in the release gate and would have caught
  fz_kwdflow at a release rather than at a push.
* utxo: the set is opaque, and read an entry at a time
  kw_utxoset was a transparent struct holding a pointer to an array that grows
  and a transaction per entry, which a caller declared by value and indexed
  into. It is a handle from kw_utxoset_new now, and kw_utxoset_at hands out one
  entry. kw_utxo itself stays a plain record: what a caller wants of the set is
  an entry's value, script and height, not its array.

  kw_utxoset_init is gone. Seven of its callers in kw ignored the return, so an
  allocation failure left a set whose array was NULL and whose count read 0,
  which is a wallet reporting an empty balance rather than a failure; each one
  checks now.
* tx: opaque, and read through accessors
  kw_tx was a transparent 63264-byte struct, which a caller declared on its
  frame and read vin[i].script out of directly. It is a handle now, from
  kw_tx_new, and five accessors cover every field a caller read. kw_tx_free
  zeroes before releasing, since a signed transaction carries signatures.

  Two Werror flags come with it. &handle where handle is wanted is kw_tx **
  against kw_tx *, which was a warning in a build that emits none anyone reads,
  and it compiles into a call that hashes the wrong bytes: that is how four
  cosign sites and one in a fuzz harness went unnoticed. Promoted to errors
  along with int-conversion, which is the same mistake spelled differently.

  crypto/tx_internal.h carries the layout for the library's own code and for the
  three tests that check the serializer and the sighash against byte vectors.
  It is not installed.
* psbt: opaque, and read through accessors
  kw_psbt was a transparent 182048-byte struct callers put on their frames, and
  its layout has changed twice. It is a handle now, from kw_psbt_new, and seven
  accessors cover every field a caller read; each returns 0 for an absent field
  rather than a zero length, since a caller that has to know an absent redeem
  script reads as redeemlen == 0 can mistake one for the other, which is how
  kw_psbt_sign came to refuse every p2pkh input.

  The test had been shallow-copying the struct twenty times, sharing the heap
  pointers its previous transactions live behind and freeing none of the copies.
  That was safe only because combine replaces a utxo when the destination has
  none, and these always had one. The type makes it impossible rather than
  coincidental.

  crypto/psbt_internal.h carries the layout for this project's tests and is not
  installed: 11 of the 13 internal writes in test_psbt forge a signature under
  another party's pubkey or a sighash the signer never asked for, which arrive
  as bytes, so the faithful test splices the pair into a serialized psbt. That
  is not done and the header says so.
* bip32: lock the intermediate keys a path walk materialises
  m/44'/coin'/account'/change/index produces a private key at every step, and
  the walker kept each on an unlocked page for the length of the walk, zeroing
  it afterwards. Zeroing is not the same as keeping the page off a disk, and no
  caller could fix it, since it never sees those keys. The hmac output whose
  left half becomes the child secret and the copy of a parent's secret that a
  hardened index makes were unlocked for the same reason.

  The threat model said the child keys derived from the seed are locked and
  those are those keys, so the document was ahead of the code. Locked once for
  the length of the function and forgotten on one path, so the early returns
  cannot leave a lock behind. 200 derivations in one run raise no lock
  complaint: the counting is per page and these share two.
* kw: sign --raw, so its output goes straight into send
  sign prints five lines and send --tx - reads one of hex, so the two could not
  be joined without an awk in between. --raw puts the transaction alone on
  stdout and moves the decoded outputs and the fee to stderr rather than
  dropping them: a pipeline that skips the readback should be the caller saying
  --yes, not a consequence of redirecting stdout. The default output is
  unchanged, which the test asserts alongside the pipeline.
* docs: ship the public key that signs the tags
  SECURITY.md named a fingerprint and said to run git tag -v, which needs a key
  the reader does not have, from a keyserver that may not have it either.
  docs/bluezr.asc is the key. It also says what the file does not prove: whoever
  could rewrite this history could put their own key beside their own
  fingerprint and both would agree, so the fingerprint has to come from
  somewhere that is not this repository.
* net: the chain half's diagnostics through the sink too, and the global gone
  42 fprintf(stderr, ...) calls across sync, psync, cf, cfstore and chainsel,
  and kw_net_verbose with them: 25 traces, 17 errors, and the sink decides what
  to do with each rather than a library global deciding whether to format it.
  kw, kwd and kwui carry want_trace, set where the global was, so the output is
  what it was; a trace still reads "[headers] 20 synced" with no prefix.
  Neither archive references the process's stderr or stdout from any object.
* log: the library says nothing unless a caller asks it to
  A library that writes to stderr decides where a daemon's, a gui's or a wasm
  build's output goes, and a caller gets koinu's prose in its own output with no
  way to stop it. crypto/log.h takes a sink and is silent without one; kw, kwd
  and kwui install one that writes to stderr with the same wording, so nothing a
  user sees changes. Two levels, because the messages are two kinds: a refusal
  the user needs either way, and progress, which is what --verbose meant.

  The signing half had exactly one such line, the mlock failure in crypto/mem.c,
  so this is a one-object change there rather than the sweep the count suggests:
  of the 69 printf calls in the library, 22 are snprintf into a buffer and 7
  write the utxo set to a file it was given. test_split.sh now fails if any
  object in the signing archive references stderr or stdout, and names it. The
  chain half still has 49 of them, gated on kw_net_verbose, and is next.
* build: make install, pkg-config, and one header for the signing half
  include/koinu-sign.h is the whole of libkoinu-sign.a behind a single include,
  and make install places it with the archives, the pkg-config files and the
  binaries under PREFIX. test_install.sh installs into a throwaway DESTDIR and
  compiles test/consumer.c with only the installed prefix on the include path,
  which is what catches a public header that includes a private one: adding
  cpu.h to tx.h fails it. uninstall has to take back what it placed.

  secp256k1 is not installed, because a second libsecp256k1 on a system is how
  a program links two of them; the .pc declares it in Libs.private, which does
  not demand a libsecp256k1.pc that may be absent even where the library is not.

  No shared library and no SONAME. The types in those headers are transparent
  structs that still change, so a version number on a .so would be one this
  project breaks on its next commit, and the header says so rather than
  implying otherwise.
* build: prefix the vendored primitives' symbol names
  argon2, its blake2b and poly1305-donna export 55 names without a namespace,
  among them initialize, finalize, allocate_memory, free_memory, copy_block,
  encode_string and decode_string. A program defining any of those could not
  link libkoinu-sign.a: the linker reported four multiple definitions and
  stopped, and one that vendored argon2 itself got whichever copy came first
  with no diagnostic at all. crypto/vendor/kw_symbols.h renames them to
  kw_vendor_* and is force-included by CPPFLAGS, so the vendored sources stay
  as they came and PROVENANCE's hashes still describe them. test_split.sh fails
  on any exported name outside kw_ and KW_, and links a program that keeps five
  of them for itself.
* psbt: a spend built without a key and signed without a socket
  without a socket
  kw psbt build takes the account public key and the utxo set, chooses the
  coins, picks the change index by the rule a keyed build uses, settles the fee
  and prints a psbt carrying the transaction behind every input. kw psbt sign
  --keystore holds the seed, signs and finalizes the inputs whose funding
  output pays an address the wallet derives, and opens no socket. kw psbt
  extract then feeds kw send.

  kw_psbt_sign refused an input with no redeem script, so only a co-signature
  could cross as a psbt and a wallet's own p2pkh spend could not. It now takes
  the scriptCode from the previous transaction for either shape, and for p2pkh
  requires the funding output to pay the key being used, which is what stops a
  psbt naming another party's coin and collecting a signature over it.

  kw_change_index_pub answers the change question from the account public key
  over the same rule as the keyed path, since two front ends rotating
  differently put change on one address at two times. test_change requires the
  two to agree for every gap from 0 to 8.
* build: the signing half as its own archive, with a gate on it
  The threat model's boundary is enforced per invocation because kw links the
  p2p parsers whether a command uses them or not. The core now builds as
  libkoinu-sign.a and libkoinu-chain.a as well as libkw.a: the signing half is
  the keys, derivations, share formats, keystore, transaction builder, psbt and
  utxo tracking, and references no function that can open a connection.
  test/test_split.sh reads the archive's undefined symbols, requires the chain
  half to reference some so the pattern is known to match, and links a signer
  against the signing half alone. Putting net/peer.c in the signing half fails
  it on connect, setsockopt and socket.
* powq: take the auxpow chain id from the chain, not from a constant
* kwui: pin the key the send flow signs with
* utxo: bind every amount to the transaction that created it
  Legacy sighash does not commit to input amounts, so a signer reading a utxo
  set believed whatever value the file stated and paid the difference to the
  miner: one edited value column turned a 1000 DOGE sweep into a 998 DOGE fee
  reported as 0.000192, mined on regtest. The set now carries the creating
  transaction and loading checks each entry against it, so a value a file
  cannot prove is a load that fails rather than a fee that is paid.
* slip39: a group threshold of one over several groups is a real layout
  Split refused it as a threshold that hands out copies, which is the spec's
  rule for member shares and not for groups: each group holds the same group
  share and splits it its own way, so "my share, or two of the family's" is
  exactly what it says. It was 43 of 150 random layouts in a differential run
  against the reference library, and the layout the help text uses as its
  example.
* slip39, codex32: branchless field arithmetic
  Both interpolations multiplied secret share bytes through table lookups and
  a branch on whether the byte was zero, so the cache line touched and the work
  done followed the secret. Neither uses a table now, and the operation
  sequence is fixed. Checked against both specs' own formulations over every
  pair in both fields.
* tx: size the scriptCode to a redeem script, not to a scriptPubKey
  kw_tx_sighash hashed through a 256-byte buffer while a psbt holds the 520 a
  pushed element may be, so a 1-of-8 multisig redeem script at 275 bytes was
  stored and then refused at signing with no reason given.
* codex32: zero the decoded share whole, padding included
  Two decoded shares compared as bytes read the alignment hole before nsym,
  which is whatever the stack held. Found by the new fuzz harness, whose first
  crash would not reproduce.
* fuzz: a harness for both share formats
  Neither decoder had any coverage. decode, encode and combine for SLIP-39 and
  codex32 off one corpus, seeded from the official vectors, since from noise
  the checksums refuse everything and combine is never reached. 7.4M runs clean.
* sweep: two commands, so the run that holds the key opens no socket
  The threat model said the process holding a key never opens a socket, and
  sweep enforced something weaker: it wiped the WIF before connecting and read
  it again after closing the peer, so no secret was resident while a socket was
  open, but the p2p parser and the signer were one process and a corruption
  reached during the sync ran code in the process that read the key next.
  `--watch` now finds the coins and reads no key; `--wif --utxos` signs and
  opens no socket. The signing step also refuses any output in the file that is
  not locked to the key it holds, which the single run could not get wrong and
  so never checked. The threat model says what is enforced per command and what
  separate executables would make structural.
* kwui: bound the send destination by what the journal can record
  send_flow read the destination into 80 bytes more than the journal's address
  field holds, so an address too long for it was recorded truncated rather than
  refused, and the change rotation reads that field back. The buffer is the
  journal's size now, so a paste too long fails addr_to_spk and says so. No
  base58check address comes near either bound.
* docs: say that --recursive is not optional
  A plain clone leaves depends/secp256k1 empty and make stops on a missing
  secp256k1.h, which reads as a broken build rather than a missing submodule.
  Names the fix for a clone that already exists, since that is the case the flag
  cannot help.
* test: clear the five warnings a clean build still prints
  kw_outpoint_status has four members and test_spv initialised three of them by
  position, so -Wmissing-field-initializers fired at four sites; `{ 0 }` says the
  same thing and keeps saying it when the struct grows. locked_bytes read into
  buf + held with a length of sizeof buf - held - 1, and nothing in the loop told
  the compiler held stays under the buffer, so -Wstringop-overflow could not rule
  out the underflow. The bound is in the condition now and an over-long line is
  dropped rather than stopping the read.
* slip39: split the seed into shares, and combine a threshold back
  A written mnemonic is one copy, so losing the wallet and having it stolen are
  the same number. `kw backup split` makes SLIP-39 shares of the 64-byte seed
  and `kw backup combine` seals a keystore from a threshold of them, with the
  two numbers set apart. The spec mandates the BIP32 master seed as the secret
  to split, so a threshold restores the same wallet in any implementation; a
  512-bit secret gives 59-word shares, which Trezor firmware will not type.
  All 45 official vectors pass, 30 of them refusals, each recovered secret
  checked against the vector's xprv.
* codex32: the same split in base32, checkable with a pen
  `--format codex32` writes BIP-93 strings, whose checksum and whose Shamir
  arithmetic are both over GF(32) and small enough to compute by hand, so a
  backup can be verified without trusting the machine that reads it. It gives
  up the passphrase, the digest and the grouping for that: one flat threshold,
  and nothing in the format says a set reconstructs the seed it came from.
  `backup combine` reads the format off the shares. Every BIP-93 vector passes,
  including all 55 that must be refused and every derived share byte for byte.
* gitignore wallet data, as a backstop against a stray add
  Keystores, utxo sets, journals and header caches are ignored, so a `git add`
  with a wide pattern in a working directory cannot commit a wallet.
* kw: watch a wallet from its account xpub, with no keys on that machine
  Signing already happened where no socket was open, since `kw sign` writes a
  file and `kw send` broadcasts it, but the online side had nothing to watch
  with: the choice was the keystore on the connected machine or no watching at
  all. `export xpub` prints the account public key for m/44'/coin'/account' and
  `scan --xpub` derives every address under it with no keystore, no passphrase
  and no secret in the process, change and index being unhardened so a public
  parent walks them. An extended private key is refused there, and giving both a
  keystore and an xpub is refused rather than one quietly winning.
* scan: record what left as well as what arrived, so the journal is a history
  The utxo set answers what a wallet holds, and a coin received and then spent is
  not in it while a payment out leaves nothing behind at all, so a wallet
  restored from its words could say what it holds and not what it has done. The
  scan already walks both directions and the removal was silent. A utxo set
  carries an optional observer now, which is where the scan hangs a journal
  writer, and the entries dedup on (txid, vout, direction), so the rescans the
  gap rule triggers do not double anything.
* kw: ask for some of the words back before the keystore exists
  The cheapest moment to catch a phrase written down wrong is while it is still
  on the screen, and `kw new` never looked. It asks for four of the 24 words by
  position, three of 12, with three attempts, and seals nothing if they do not
  come back: the words were never written anywhere, so a refusal costs a keystore
  that did not exist. Skipped when stdin is not a terminal, which is every script
  and every test, and said on stderr rather than silently.
* kw: backup verify, so a phrase can be checked without being restored
  Coins lost to key handling are mostly lost to a backup nobody checked, and
  checking one meant restoring it somewhere: the words and a wallet in one place
  at one time, which is the situation a backup exists to avoid. `backup verify`
  derives the seed the typed words give, opens the keystore and compares the two
  with kw_memcmp_ct. Neither is printed and nothing is written. A match exits 0,
  a mismatch exits 3 and says that a wallet sealed with a seed passphrase needs
  one here too. With no `--keystore` it prints the master fingerprint and the
  first address, which are not secrets, so a paper backup can be checked against
  an address already known.
* kw: a BIP39 passphrase, so a stolen phrase does not spend
  kw_bip39_to_seed was called with an empty passphrase on both paths, so the
  words were the whole secret and anyone who read them spent the wallet.
  `--seed-passphrase` on new and restore goes into the seed derivation, which
  makes the words alone restore a different wallet. It is a different secret from
  `--passphrase`, which seals the keystore, and the help says so, because
  confusing the two would cost someone their coins. Nothing checks it: every
  passphrase yields a valid wallet, so a wrong one restores an empty wallet
  rather than reporting a mistake, and a forgotten one is as final as a lost
  phrase. The first address printed at restore is the only check there is.
* kw: sign reports what it signed, read back out of the bytes
  sign printed a fee of total_in - send_amt - change and an address from the
  request, so the summary and the transaction were two statements of the same
  intention rather than one checking the other: a builder that paid the wrong
  amount, the wrong script, or an extra output would have printed the right
  numbers anyway. The outputs are decoded from the serialized transaction now and
  printed by index, and the fee is the selected inputs less the decoded output
  total. Four refusals come with it, each a mistake that cannot be taken back
  once broadcast: an output count that is not what was built, a destination
  script or amount that is not what was asked for, a change output that is not
  the address this wallet derived, and outputs worth more than the inputs.
* docs: say where the boundary is before saying anything else
  The threat model described what is verified and what is trusted, spread over
  the sections that cover each, so a reader deciding whether to run this had to
  assemble the answer themselves. It opens with the boundary in four sentences
  now: a compromised kwd cannot sign, a compromised machine running kw can, no
  wallet can undo a payment its owner approved, and a seed lost with the wallet
  file is gone because the keystore holds the seed and not the words. Also what
  it will not grow: server-side recovery, a login, telemetry, or any convenience
  that needs the key process to reach the network.

**Full Changelog**: https://github.com/xanimo/koinu/compare/v0.3.0...v0.4.0

## [0.3.0] - 2026-10-10

## Upgrading from 0.2.x

Rescan. A utxo set written by 0.2.x has no `# end` line, so it does not load and
sign reports no utxo set until `kw scan` writes a new one. Nothing is lost by it:
the set is derived from the chain.

What a caller has to change:

- `kw psbt sign` and `kw cosign` require `--utxo`, the raw transaction holding
  the coin being spent, so the script being signed is tied to what that coin is
  locked to.
- `kw_block_find_outpoint` takes the scriptPubKey being waited on. An outpoint
  alone says where a payment sits and not who it pays.
- `kwd` refuses a request with no since height, and `kw outpoint --daemon` now
  refuses to send one without `--since`.
- `kw outpoint --daemon` and `kwd` take one spelling of an outpoint: one colon, a
  64-character lowercase txid, and a vout with no leading zero.
- Numeric arguments that 0.2.x read loosely are refused: `--input`'s key index,
  an outpoint vout past 2^32, and anything with trailing characters.

Exit codes, which 0.2.x did not have:

    0   done
    1   refused, with a reason
    2   usage, or a flag the command needs and did not get
    3   outpoint: spent, or not in the set the scan built
    4   outpoint: not seen in the range asked for
        send: the node does not hold the transaction, or cannot be asked
    5   an immature coinbase: held, not spendable yet

kwd answers with the same number in front of its reply line.

## What's Changed
* kwd: check the work of the chain it answers from, and weigh several peers
  kwd answered confirmations from a chain it never checked the work of. It now
  validates proof of work, weighs what several peers serve and refuses to answer
  below the newest anchor.
* test: say when the scrypt comparison was portable against itself
* chainsel: a peer forking from genesis is not a peer to drop
* psync: test the downloader, fsync before the rename, bound the span
* headers: load the cache in chunks, and build records where they live
* docs: cut the framing and the bold lead-ins
* kwui: filter the journal address before printing it
* build: make builds kw, kwd and kwui, which the README documents
* docs: say who can talk to kwd's socket
* gitignore the two new test binaries
* kw: resolve the dns seeds for any command that needs a peer
  Commands other than sync took --node or nothing, so the seeds the chain
  parameters carry were only used by one path.
* psync: give up when the fill stalls, not when it has a bad run
* psync: a racing loser is not evidence of a stall
* cf: say when a peer cannot serve filters, because none of them can
* cf: answer a bounded query without filters, so kwd runs on the public network
  Too few mainnet nodes serve BIP158 for a filter query to find one reliably, so a
  bounded height range falls back to downloading the blocks.
* kwd: a second signal exits, and the README carries measured latency
* gitignore net_services
* gitignore header caches and cfcheckpoints output
* socks5: a domain bound address needs 255 bytes, not 16
* psync: fill the thread array at started, not at i
* keystore: fsync the seal, zero scratch on error paths, harden the build
* mem: actually lock the seed, which the threat model has been claiming
  kw_mlock had no callers anywhere in the tree while the threat model said the
  seed was locked, so a machine with swap could write 64 bytes of seed to disk in
  the clear.
* kw: stop reading secrets through getline
* kwui: the same secret handling as kw, not a second copy of the old one
* psbt: refuse what it cannot represent instead of quietly resolving it
* sync: bound the detour, and kwd's numeric arguments
* fuzz: drive the merged-mining structure check
* crypto: size by division and refuse a wrapped stream counter
* gcs: widen a varint that truncates on i386
* bip32: skip a rejected child rather than failing the branch
* change: check the pubkey, and say when rotation runs out
* utxo: tie the sscanf width to KW_SPK_MAX
* mem: name the constant-time compare for memcmp, not equality
* build: make tsan leave an unsanitized library behind it
* kw: read secrets without stdio's buffer in between
* psync: bound the segment, not just the run
* cf: bound the unfiltered span by the span
* psbt: refuse two signatures under one key
* journal: make the name durable on the write that creates it
* docs: say what is not locked, and which finalize checks
* kw: filter a peer's reject reason before printing it
* cfstore: range-check the index offset before it narrows
* tx: say kw_tx_parse's limits are the wallet's, not consensus
* keystore: wipe the derived key when the kdf fails
* mem: count the page locks so one secret cannot unlock another
* bip39: seed from the words, not from the spacing
* base58: wipe the decoded digits on every return
* bip32: refuse the extended keys BIP32 calls invalid
* bip32: skip to the next index when a public child is invalid
* spv: an outpoint is not a payment unless it pays the watched script
  Breaking for callers of kw_block_find_outpoint, which now takes the
  scriptPubKey being waited on: an outpoint alone says where a payment sits and
  not who it pays, so a payer could mine an output of their own at TXID:0 and
  hand that outpoint to whoever was waiting to be paid.
* psbt: sign only what the coin being spent is locked to
  Breaking for psbt sign and cosign, which now need --utxo: the signature was
  computed over the script the psbt carried rather than the one the coin being
  spent is locked to.
* psbt: verify a counterparty's signature before combining it
* kw: check an --input amount against the tracked set
* kwui: count every address the scan watched, not kwui's own gap
* kw: bound an amount, and pay for the outputs the transaction has
* utxo: write the set privately and whole, or not at all
* spv: refuse the shapes a merkle root cannot tell apart
* net: bound every wait for a message, not just the headers one
* cfstore: follow the chain when it moves under the cache
* tx: strip OP_CODESEPARATOR from the scriptCode, as consensus does
  A signature over a scriptCode holding one was computed over bytes the network
  does not hash, so the spend was rejected with NULLFAIL. Nothing in the wallet
  produces such a script, and a counterparty's can.
* bip32: loop over indices, and bound the one a path can name
* kw: lock the keys the seed turns into, not only the seed
* chainsel: a failed single-peer sync leaves nothing in the store
* sync: a header's timestamp has to sit where the chain allows
* sync: no network accepts a target easier than its powLimit
* sync: read the header's own version, and refuse a parent with an auxpow
* headers: check the cached tip's hash, and let kwd check its anchors
* chainsel: bound the comparison by what the peers will serve
* build: make the hardening reach the link, and the ubsan gate fail
* kwd: exit on the first signal, refuse a request with no since height
* docs: say that peer choice is the weakest link, and pin the checkout action
* fuzz: cover the version, block, filter, cache and keystore parsers
* cfstore: bound every offset the index hands back, and the feefilter shift
* peer: bound one exchange, since a feefilter never reaches a caller
* kw: cosign only a script that names the signing key
* sync: follow a reorg on one peer instead of wedging the cache
* mem: no core dumps, and write the mnemonic without stdio
* scan: an address that was paid stays used, even once it is spent
* kw: ask the node whether it holds the transaction, rather than reading silence
  A node has no acknowledgement for a transaction it accepted, so send asks for
  it back after broadcasting and exits 4 when the node does not hold it, and when
  the node cannot be asked at all, which is a node run with -peerbloomfilters=0.
* socks5: a fresh credential pair per connection, so tor isolates the streams
  Without credentials every connection could share one circuit and one exit,
  which is the comparison the threat model relies on above the newest anchor.
* kw: one spelling per outpoint, and no empty passphrase
* utxo: track a coinbase, and refuse to call an immature one spendable
  A coinbase output under 60 confirmations is no longer selected, and send exits
  5 when that is the only thing left to spend.
* kw: --validate-pow syncs the chain it checks, on every command
  The flag checked whatever headers happened to be cached.
* docs: say what the tree does, and derive the user agent from the version
* fuzz: eight stateful harnesses over the network flows
* cfstore: fsync the filters before the sidecar vouches for them
* test: count tor's circuits instead of trusting the credentials
* sync: demand the base version BIP66 and BIP65 made mandatory
  A chain of base version 2 headers was a valid chain to this wallet all the way
  to the tip. The activation heights come from dogecoin's chainparams.cpp.
* sync: rehash every cached record above the newest anchor
  A KWH2 cache stores each header's hash beside it and the load trusted it, so
  edited raw bytes with consistent stored hashes survived: above the newest
  anchor that is what the timestamp, retarget and work rules read.
* chainparams: anchor 6400000
  The tail a cold sync checks the slow way drops from 32315 headers to 7315.
* chainparams: filter anchor 6400000

* docs: a features list and the sync numbers as measured today
* docs: say that the fuzz gate needs setarch -R on this host
* kw: wait out the node's inventory tick before calling a send unknown
  A node answers the BIP35 probe on its own inventory timer, averaging five
  seconds, and send gave up at ten: about one send in eight reported "unknown"
  with exit 4 for a transaction the node had accepted.
* utxo: initialise the used flag, which the scan reads to size its window
* kw: refuse an empty passphrase when sealing, not when opening
  0.2.5 sealed keystores with an empty passphrase and the refusal applied to
  opening too, locking those owners out of their own wallets.
* spv: read a block holding a 64-byte transaction instead of refusing it
  A standard p2sh spend of that size exists and is mined, and refusing the
  length made every scan, outpoint and kwd query over its block fail. For one
  fee anyone could have stopped them.
* auxpow: make the parent rules the ones core actually applies
* sync: account for every fork in an exchange, not only the first
  A peer forking twice in one exchange truncated the store with the headers
  between the two forks saved nowhere, and the next sync appended its lighter
  chain with no work compared.
* sync: keep the headers below one the chain refuses, and read the clock per batch
  One header past the two-hour bound discarded the whole sync, and the bound
  read the clock once, so a sequential mainnet sync taking longer than two hours
  failed at its last batch every time.
* utxo: take coinbase maturity from the chain, and record the height scanned
  Maturity was 60 everywhere, where core wants 30 below height 145000 and 240
  above it on mainnet and testnet, so a mainnet coinbase at depth 60 was offered
  for spending and refused by the node. The scan also recorded the headers it
  appended as the height it had reached, so a second scan with --headers made
  every coinbase read as immature.
* kw: cosign only a script that names more than this key
  Breaking: cosign requires --utxo now. A script naming one key spends with that
  key alone however it is dressed up, so --redeem set to a p2pk or 1-of-1 script
  over a coin that key holds turned a co-signature into a complete spend of it.
* chainsel: bound the comparison by what the peers agree on, not the loudest
  One peer advertising 2^31-1 pushed the span past the cap and collapsed the
  multi-peer comparison to a single peer, which could be that one.
* kw: do not ask a node that cannot answer, and bound what it may say instead
* psbt: verify every signature a combine holds, not only the arriving ones
* utxo: do not write the set through a symlink left at the temp path
* tx: start the scriptCode at the separator its checksig executed after
  A separator executing before the CHECKSIG moves where the scriptCode starts
  and one after it does not, so signatures over such scripts were refused on
  chain and psbt combine judged them by the same wrong digest.
* cfstore: walk a cache longer than the chain back, rather than refusing it
* net: bound a wait in time, which is what peer.h already claimed
* kw: one spelling per outpoint, and a parsed key index
* kwui: size the address list from the scan's extent, not a fixed 200
  kwui capped at 100 addresses per chain while scan watches up to 20000, so a
  wallet with coins past that showed a balance short of what it holds.
* kw: ask for the passphrase before showing the mnemonic, and check it was written
  kw new printed the mnemonic first, so a refused passphrase left it on screen
  with no keystore, and an unwritable stdout sealed a keystore whose only backup
  went nowhere while exiting 0.
* kw: bound what the --input amounts add up to, and say when nothing checks them
* build: make fuzz builds with -fno-sanitize-recover, as every other gate does
* kw: the smaller things the review listed, one pass
* gitignore the fuzz binaries make fuzz and fuzz-net build

**Full Changelog**: https://github.com/xanimo/koinu/compare/v0.2.5...v0.3.0

## [0.2.5] - 2026-09-15
## What's Changed
* auxpow: hash the parent coinbase's txid, not its wtxid
  A merged-mined header was refused whenever the parent's coinbase carried a
  witness, which litecoin's have since 2017. The txid in the parent's merkle tree
  covers the transaction with the witness taken out; the check hashed the bytes as
  they arrived, which is the wtxid, so the root never matched. About 2% of recent
  mainnet headers, the first of them 67 blocks above the newest anchor, so every
  command that syncs headers past an anchor died there reporting "does not prove
  its work". No release that checks work could sync mainnet. Upgrade from 0.2.4.
* chainparams: anchor 6375000
* kw: exit 2 when a broadcast needs --yes

**Full Changelog**: https://github.com/xanimo/koinu/compare/v0.2.4...v0.2.5

## [0.2.4] - 2026-09-14
## What's Changed
* kw: send decodes what it is about to broadcast
  Breaking for anything driving send non-interactively: it prints the destination,
  amount and fee and then asks for confirmation, and a caller whose stdin is not a
  terminal has to pass --yes or the broadcast is refused. It exits 2 for that, so a
  caller can tell a missing flag from a node that rejected the transaction.
* sync: a header must carry the difficulty the chain demands of it
* sha2: the x86 core has been run on hardware that has the instruction
* make asan: put the tree back in release shape when it passes
* test: the sighash against 322 spends the network already accepted
* bip32: propagate the failure a void return was throwing away
* ec: pin low-S and strict DER, which a downstream now depends on
* fix a stack overflow in the utxo loader, and fuzz the files it forgot
* keystore: spend the headroom on memory, not passes
* utxo: refuse a value that would wrap the total, and say when a load is partial
* kw: no key in memory while a peer socket is open
  scan derives its watch addresses before opening a socket, four times --gap per
  chain, and a wallet whose used addresses run past that is asked to re-run with a
  larger --gap rather than being watched short. Deriving costs 0.24s at --gap 20,
  0.88s at 500 and 6.8s at 5000. sweep needs --wif @FILE to re-read the key after
  the peer is closed.
* sync: check the anchors on the default path, not only the parallel one
* sync: check a cached chain against the anchors when it is loaded
* spv: check the body against the header's merkle root
  A block body was never checked against the header's merkle root, so a peer could
  answer with the header asked for and a body of its own invention: a fabricated
  transaction paying a watched address credited 500000000000 koinu, and
  kw_block_find_outpoint reported the made-up outpoint as unspent. A level with an
  equal adjacent pair is refused with it (CVE-2012-2459). Anything pinning koinu as
  a confirmation backend wants this release or later.
* cf: enforce the filter-header anchors on the uncached path too
* cfstore: refuse a filter cache the sidecar does not cover
* kw: bound the peer's fee floor, rotate change, refuse extra inputs
* wallet: rotate change by one rule both front ends use
* kwd: bound a client's read, close the socket-mode window, redial the peer
* sync: hash the raw header at each anchor, not the cache's own hash
* base58: look a digit up without a branch or a table
* spv: build each block's merkle tree once, not twice
* change: initialise the journal before anything can skip it
* docs: the threat model described an older program
* build: make the two new link rules depend on secp, not just link it
* build: say what to do when the submodule is missing
* sync: a real locator, a work sum, and a store that can roll back
* chainsel: keep the chain with the most work, not the first one served
* kw: ask three peers for headers and keep the heaviest chain
* docs: record what weighing several peers' chains does and does not do
* kw: one header sync for every command, so outpoint checks work too
  outpoint, sweep, height and cfcheckpoints synced headers with no validator pool,
  so they checked no work at all while scan checked every header above the newest
  anchor. outpoint is the command a payment backend calls. All five share one sync
  now, and outpoint has a live test for the first time.
* docs: the work check is per command, and it was not

**Full Changelog**: https://github.com/xanimo/koinu/compare/v0.2.3...v0.2.4

## [0.2.3] - 2026-09-11
## What's Changed
* kw: bound the fee a spend may pay
* cf: anchor the filter-header chain to the release
* psync: let the rate-aware picker actually pick
* scrypt, the hash dogecoin's proof of work is built on
* gitignore the scrypt test binary
* scrypt: eight headers at once on avx2
* cpu: one place that asks what the machine can run
* pow: compact targets and the work a chain represents
* test: hash a real header, not one that only looks like one
* kwui: hold a spend to the same rules kw send does
* kwui: refresh without restarting
* kwui: an address screen and a coins screen
* wallet: a journal, so a spend and a receive leave a record
* test: scan against a regtest node, and the receives it records
* pow: the retarget rule, both regimes and the switch between them
* auxpow: verify the proof a merged-mined block borrows from its parent
* test: three real mainnet merged-mining proofs, fetched from a peer
* powq: check proof of work off the download's back, in parallel
* kw: scan checks the work of every header past the last anchor
* sha2: unroll the compression, and stop double hashing the long way round
* sha2: the sha-256 instructions, where the cpu has them and they agree
* docs: say how the anchors get refreshed, and add the tool that does it

**Full Changelog**: https://github.com/xanimo/koinu/compare/v0.2.2...v0.2.3

## [0.2.2] - 2026-09-09
## What's Changed
* fuzz the parsers, and rebuild on a header change
* gcs: build where there is no 128-bit integer
* ci: build on each platform and word size, not just one
* test: do not assume gnu wc output
* ci: drop the intel macos job
* docs: a threat model
* kwui: compose, confirm and sign a spend

**Full Changelog**: https://github.com/xanimo/koinu/compare/v0.2.1...v0.2.2

## [0.2.1] - 2026-09-09
## What's Changed
* tx: a scriptSig is not bounded by the scriptPubKey limit

**Full Changelog**: https://github.com/xanimo/koinu/compare/v0.2.0...v0.2.1

## [0.2.0] - 2026-09-09
## What's Changed
* kwui: a read-only terminal view of a wallet
* bip174 partially signed transactions
* psbt: test against the bip174 vectors
* kw psbt: the bip174 roles over the command line

**Full Changelog**: https://github.com/xanimo/koinu/compare/v0.1.0...v0.2.0

## [0.1.0] - 2026-09-09
## What's Changed
* the rng, secure memory, hex, sha2, ripemd160, hmac and pbkdf2
* base58 and base58check, secp256k1, bip32, bip39 and the english wordlist
* chainparams, addresses and bip44
* chacha20-poly1305, argon2id, and the keystore over them
* tx: legacy sighash and p2pkh signing, byte-exact against libdogecoin
* net: p2p framing, the version handshake, and a peer transport
* headers: the 80-byte header, getheaders, the store, and auxpow skipping
* sync: the header sync driver
* wallet: the watchset and utxo set, driven by a legacy tx walker
* spv: full-block download and local scanning
* gcs and cf: bip158 filters and the bip157 backend
* socks5: every connection over tor
* kw new, restore and address
* kw scan and sign from the tracked utxo set
* kw sign: estimate the fee from size and the relay floor
* feefilter-adaptive fee: default the sign rate to the peer's floor
* kw scan: gap-limit auto-extension
* kw sweep: move an external wif key's funds into the wallet
* kw sweep: accept uncompressed wifs
* kw height and kw outpoint
* header chain on-disk cache
* KWH2 header cache: store the hash with each header
* kw send: broadcast a raw transaction over p2p
* on-disk filter cache for local outpoint lookups
* kw outpoint --since: height-bounded spend detection
* kwd: resident daemon for sub-second outpoint confirmation
* tx: p2sh multisig co-signing
* kw cosign: co-sign a P2SH multisig spend from the command line
* cf: verify filter commitments against the cfheaders chain
* parallel checkpointed header download
* parallel sync: spread over several nodes, denser anchors, delta save
* resolve peers from the dns seeds when no --node is given
* psync: race straggler segments, buffer before write
* psync: pick peers by measured rate
* README: document the wallet that exists, and kw --version

**Full Changelog**: https://github.com/xanimo/koinu/commits/v0.1.0
