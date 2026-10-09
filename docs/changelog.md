# Changelog

## [Unreleased]

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
* kw: cosign only a script that cannot be spent with the signing key alone
  Breaking: cosign requires --utxo now. A p2pk script names the signing key, so
  --redeem set to the p2pk scriptPubKey of a coin that key holds turned a
  co-signature into a complete spend of it.
* chainsel: bound the comparison by what the peers agree on, not the loudest
  One peer advertising 2^31-1 pushed the span past the cap and collapsed the
  multi-peer comparison to a single peer, which could be that one.
* kw: do not ask a node that cannot answer, and bound what it may say instead
* psbt: verify every signature a combine holds, not only the arriving ones
* utxo: do not write the set through a symlink left at the temp path
* tx: start the scriptCode at the separator that ran, not at the script
  A separator executing before the CHECKSIG moves where the scriptCode starts,
  so signatures over such a script were refused on chain.
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
