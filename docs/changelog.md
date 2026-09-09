# Changelog

## [Unreleased]

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
