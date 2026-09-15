# Changelog

## [Unreleased]

## [0.2.4] - 2026-09-14
## What's Changed
* kw: send decodes what it is about to broadcast
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
