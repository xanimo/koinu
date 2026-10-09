# koinu

a dogecoin wallet in c, built from the crypto up. secp256k1 is the only
submodule; everything else it needs cryptographically lives in crypto/, either
vendored from a named upstream at a named commit or written here, and frozen.

## features

- bip39 mnemonics of 12 or 24 words, bip32 derivation and bip44 accounts, with
  the seed sealed under argon2id and chacha20-poly1305
- p2pkh addresses, wif import and base58check on mainnet, testnet and regtest
- legacy transaction building, signing and verification, byte-for-byte against
  libdogecoin's signer on 322 spends the network already accepted
- p2sh multisig co-signing, and the bip174 psbt subset dogecoin needs
- utxo tracking read off the chain itself, with coinbase maturity, change
  rotation and a fee defaulting to the peer's advertised relay floor
- header sync checking scrypt proof of work, the auxpow merged-mining proof,
  the digishield retarget, median time past, the bip66 and bip65 version floors
  and the compiled-in anchors
- parallel header download over as many connections as asked for, spread across
  up to 8 nodes or the chain's dns seeds, split at the anchors, each worker
  migrating to whichever host proves fastest
- bip157/158 compact filters with the filter-header chain verified against the
  peer's own commitments, or full-block spv where no peer serves filters
- block bodies checked against the header's merkle root, CVE-2012-2459 included
- tor through socks5 with a fresh credential pair per connection, so two
  connections do not share a circuit
- kwd, a resident daemon answering outpoint queries over a unix socket, and
  kwui, a read-only terminal view of a wallet
- one submodule: libsecp256k1. sha2, ripemd160, hmac, pbkdf2, scrypt, argon2id,
  chacha20-poly1305, siphash, base58 and the bip158 gcs are in crypto/, each
  vendored from a named upstream at a named commit or written here

## building

    git clone --recursive https://github.com/xanimo/koinu
    make check      # builds libkw.a and kw, runs the tests
    make asan       # the same under address and undefined-behaviour sanitizers

the tests cover every primitive against published vectors where they exist:
sha2, ripemd160, hmac, pbkdf2, base58, secp256k1, bip32, bip39, argon2id,
chacha20-poly1305, bip158 filters, and the transaction signer byte-for-byte
against libdogecoin's.

## layout

a library core (libkw.a) with a thin cli on top: the core owns the crypto, the
keys and the wallet state, and the cli stays dumb. crypto/ is the frozen
primitives, net/ the p2p and chain sync, wallet/ the utxo tracking.
docs/PROVENANCE.md records the secp256k1 pin and where every vendored primitive
came from.

## kw

the keystore holds the bip39 seed sealed under argon2id and chacha20-poly1305.
the mnemonic is printed once at creation and never stored, so it is the only
backup.

    kw new     --keystore w.ks               generate, seal, show the mnemonic
    kw restore --keystore w.ks --mnemonic -  seal an existing mnemonic
    kw address --keystore w.ks               derive m/44'/coin'/0'/0/index

spending takes three commands. scan watches the first --gap receive and change
addresses and writes the utxo set beside the keystore, extending the range
automatically until enough unused addresses trail the highest used one. sign
selects inputs from that set and builds the transaction. send broadcasts it.

    kw scan --keystore w.ks --node NODE --headers h --filters f
    kw sign --keystore w.ks --to DEST:100
    kw send --tx @tx.hex --node NODE          decodes it and asks first

send asks the node for its mempool afterwards and looks for the transaction in
what comes back, since a node acknowledges nothing it accepts: exit 0 and
"broadcast" mean the node listed it, exit 4 and "unknown" mean no reject arrived
and it did not list it, which is what an orphan or a repeat of something already
rejected looks like, and exit 1 means a reject with the node's reason.

the fee defaults to the peer's advertised relay floor, captured during scan;
--feerate sets a rate and --fee an exact amount. change below the dust limit
goes to the fee instead of an output.

    kw height   --headers h                  the tip height and hash
    kw outpoint --watch ADDR --outpoint TXID:VOUT --since HEIGHT
    kw sweep    --wif @k --to DEST           spend an external key's balance
    kw cosign   --tx HEX --redeem HEX --wif @k

outpoint answers whether a funding output is confirmed, to what depth, and
whether it has been spent. --since bounds the search to a height range so a
recent outpoint resolves without touching the whole chain.

cosign signs one input of a p2sh multisig spend and prints the signature for
the counterparty; --finish combines the collected signatures with its own into
the finished transaction, checking each against the sighash first, so a
signature that would fail on chain is refused before broadcast.

psbt is the same co-signing as bip174 partially signed transactions, for a
caller that already speaks that format. each subcommand takes a psbt as hex
and prints one:

    kw psbt create   --tx HEX                 wrap an unsigned transaction
    kw psbt tx       --psbt HEX               the transaction being signed
    kw psbt sign     --psbt HEX --wif @k --redeem HEX --vin N
    kw psbt combine  --psbt HEX --psbt HEX    merge each party's signatures
    kw psbt sigs     --psbt HEX               pubkey and signature per line
    kw psbt finalize --psbt HEX --vin N --scriptsig HEX
    kw psbt extract  --psbt HEX               the transaction for kw send

tx is what a counterparty reads before it signs, rather than trusting what it
was handed. finalize takes the scriptSig from the caller because the scripts
this is for, a payment channel's OP_IF branch among them, do not classify for
any standard finalizer. the legacy field set is what dogecoin needs; a psbt
carrying segwit or unknown fields is refused rather than parsed with those
fields dropped.

the two routes do not check the same things. cosign --finish verifies every
collected signature against the sighash and refuses the set if one fails, so a
signature that would fail on chain is caught before broadcast. psbt finalize
writes the scriptSig it is given, which it cannot verify without knowing a
script it was built not to classify, so the caller checks it or nothing does.
combine refuses a conflict rather than picking a side: two parties holding
different redeem scripts, utxos, sighash types, or different signatures under
one pubkey stop the merge.

passphrases, mnemonics and private keys are read from a file (@path), stdin
(-), or a no-echo prompt, never from argv. --testnet and --regtest switch
networks. --tor routes every connection through a socks5 proxy, 127.0.0.1:9050
by default, and resolves peer names through it rather than locally.

## the chain

koinu never asks a peer about its addresses. the default backend pulls one
bip158 compact filter per block, tests the watched scripts locally, and
downloads only the blocks that match; --spv falls back to downloading full
blocks and scanning them, for peers that do not serve filters. both learn
nothing about the wallet beyond which blocks it wanted.

the filter backend needs a node you run with filters enabled. probing the peers
dogecoin's dns seeds hand out, 47 of 48 answered and none advertised bip158, so
against the public network today the filter path does not run and --spv is what
is left. kwd needs filters too, which is why it exits at startup against a seed
peer. test/net_services.c is the probe if you want to re-measure.

filters are checked against the peer's committed filter-header chain, and the
verified tip is kept beside the cache so a later delta sync has to connect to
it. --headers and --filters name caches that make a second run resume from the
stored tip instead of starting over.

    kw height --peers 24 --headers h

--peers downloads the checkpointed range of the header chain over that many
connections at once, splitting it at the chainparams anchors and verifying each
segment links internally and ends on its anchor. with no --node the peers come
from the dns seeds, and connections migrate to whichever ones prove fastest. how
long a cold sync takes is linear in the height and depends on the peers it lands
on, so the numbers below are one machine on one evening rather than a budget.

above the newest anchor a header sync asks three peers instead of one, since that
range is where a chain can differ. every command that syncs headers does it the
same way, outpoint included, which is the one a payment backend calls. each is asked where its chain leaves the one already
held, each fork is synced and checked, and the one with the most work is kept,
counting the cached chain as a candidate so a peer has to beat it. give --node
more than once to choose the peers; one of them and there is nothing to compare,
which the run says rather than implies.

## measured

a cold sync downloads and checks every header from genesis; a warm one loads the
cache and asks three peers for what sits above the newest anchor. at height
6407347 on an i5-10300H over a domestic connection, 2026-10-08, each row a
`kw height --headers h` with the flags shown:

    --peers 24                 255 s    dns seeds, 24 connections
    --peers 12                 379 s    dns seeds, 12 connections
    --node SBC --peers 12      757 s    one arm sbc, 12 connections
    --node HOST               1800 s    one public node, sequential
    --peers 12                 2.1 s    warm, nothing new to fetch

which peers the seeds hand out decides most of that: in the 24-connection run one
host served 120 of the 256 segments at 2805 hdr/s while another managed 350 hdr/s
for two. a worker leaves a slow host for a faster one rather than waiting on it.
the sbc row is the same 256 segments off one machine at a flat 740 hdr/s, which is
what a single host gives you with nothing to migrate to.

loading the 717MB cache costs 1.3 s, and checking it costs 20 ms: every anchor is
hashed, and so is every record above the newest one, which is where the timestamp,
retarget and work rules read raw bytes. rehashing all 6.4M would be 8.5 s on a cpu
without sha-ni, which is what the stored hash exists to avoid.

the test suite is 43 binaries, each against published vectors where they exist,
and the fuzz corpus replays 18 seeds under asan and ubsan before mutating.

## kwui

a terminal view of a wallet: the balance, and every derived address with what
it holds. it reads the keystore and the utxo set kw scan wrote. j and k move, u hides the addresses nothing has paid, s composes a spend, q
quits. send asks for a destination and an amount, shows the fee and the change
before anything is signed, asks for the passphrase again as the last
confirmation, and writes the signed transaction out for kw send. it never
connects to a peer, so the process holding keys is not the process talking to
them.

    kwui --keystore w.ks

## kwd

a resident daemon for a caller that asks repeatedly and cannot pay the chain load
each time. kw loads the header cache on every invocation, which is the 1.3 s above
and grows with the height; kwd pays that once at startup and holds the chain and
its peer connections open, then answers over a unix socket.

measured against mainnet at height 6380305, with a filter cache built from a node
serving bip158: 8 to 25ms for a repeated query, 287ms over an 80000 block range,
and 2884ms for the first request after startup, which pays the delta sync. without
filters the same daemon fetches every block in the range instead, which was 1572ms
for 46 blocks. the first number is the one to size a budget against and the last
is the one to size a range against.

kwd prefers a peer that serves bip158 filters and builds the filter cache at
startup. where the peer serves none, which is every stock 1.14 node, it says so
and answers from blocks instead: a request then costs every block from its
--since to the tip rather than the blocks a filter matched, bounded by the
unfiltered span cap, so --since is what keeps such a request cheap. a request
carrying no since height is refused rather than read as zero. the socket is created 0600 with
no group and no mode option, so whatever asks has to run as the user kwd runs as;
a caller under its own account gets a permission denied on a path that otherwise
looks right.

    kwd --node NODE --headers h --filters f --socket /run/kwd.sock
    kw outpoint --daemon /run/kwd.sock --watch ADDR --outpoint TXID:VOUT --since H
