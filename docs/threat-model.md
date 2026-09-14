# Threat model

What koinu defends against, what it does not, and what it takes on trust. This
is the document the README deliberately does not try to be.

## Keys

The seed is the only secret. It lives sealed in the keystore under argon2id and
chacha20-poly1305, and in memory only for as long as a command needs it, mlock'd
and wiped after. The mnemonic is printed once at creation and never stored, so a
stolen keystore without its passphrase yields nothing and a lost mnemonic cannot
be recovered from the keystore.

Passphrases, mnemonics and private keys are read from a file, from stdin, or
from a no-echo prompt. A bare value on the command line is refused, because argv
is readable by any process on the machine.

Not defended: a compromised machine. A keylogger, a debugger attached to the
process, or a reader of the swapped-out pages of another process defeats all of
the above. koinu assumes the host it runs on is honest.

## The chain

koinu is an SPV-class wallet. It never asks a peer about its addresses: the
default backend pulls one BIP158 filter per block, tests the watched scripts
locally, and downloads only the blocks that match. A peer learns which blocks
were wanted, which is a weaker signal than a bloom filter or an address query,
but not nothing: a peer that serves every filter and watches which blocks are
requested learns something about the wallet's activity. Tor puts a different
observer in that position rather than removing it.

### What is verified

**Work, above the last anchor.** Every header past the last checkpoint compiled
into chainparams is checked: its nBits must be the value the retarget rule
derives from the headers before it, not merely a value it claims, and its hash
must be under that target. A merged-mined header is checked through its AuxPoW
proof, so the parent block's work is what has to be there. `--validate-pow`
moves the floor to height 1 and trusts no anchor, at the cost of hashing the
whole chain. A header that fails stops the sync rather than being skipped.

**A block against its header.** A block body is refused unless its transactions
hash to the header's merkle root, and a tree level with an equal adjacent pair
is refused with it, since an odd level repeats its last node and the root cannot
then say which transaction list it came from (CVE-2012-2459). This is what
stands between a peer and a fabricated payment: without it a peer can serve a
genuine header with a body of its own invention.

**The checkpointed range, by anchor linkage.** Below the last anchor the
parallel download verifies that each segment links internally and ends on a hash
compiled into chainparams, and no work is checked there. A block hash pins one
chain, which is the stronger claim; work only proves energy was spent on some
chain. The anchors are only as good as the release that carries them.

### Not verified

**Nothing chooses between chains by work.** koinu syncs headers from one peer
and takes the chain that peer serves. Every header in it must prove its work, so
a chain of invented headers is refused, but a peer that withholds the tip, or
serves a real fork with less work than the one it is hiding, is believed. There
is no comparison against other peers because there is no second chain to compare
against.

**Filter commitments are anchored to the release, not to other peers.** Every
filter is checked against that peer's cfheaders chain and the verified tip is
pinned, so a peer cannot rewrite history it already served. The chain is also
checked against the filter-header anchors in chainparams, every 100000 blocks to
height 6300000, so a peer serving a different filter set is caught at the first
anchor it crosses rather than believed because it answered first. Above the last
anchor the base is still the peer's word. Compact filters are served by too few
nodes to compare peers against each other, which is why this is an anchor table
and not a quorum; the anchors are only as good as the release carrying them, and
they were generated from one node's cfheaders rather than derived from blocks.

The practical consequence: a peer cannot invent a confirmation, since above the
last anchor it would have to mine the headers and the body has to hash to the
header. It can still withhold one, or serve a real fork that omits it, and
nothing here compares that fork against a better one. For a wallet spending its
own coins this is a nuisance. For anything accepting payment on the strength of
a confirmation, prefer a node you control, which is what `--node` is for.

## Transactions

Signing is deterministic (RFC 6979) and low-S, so a repeated signature is
identical and a nonce is never reused. The signer is byte-exact against
libdogecoin's on the p2pkh vectors.

`kw psbt` and `kw cosign` verify every counterparty signature against the sighash
before assembling a spend, so a signature that would fail on chain is refused
locally rather than broadcast. A psbt carrying fields koinu cannot represent is
refused rather than parsed with those fields dropped, since a combiner that
silently discards what it does not understand loses the other party's data.

Change goes to the first address the utxo set and the journal agree is unused,
and signing records it, so consecutive spends do not share one. That means
signing the same spend twice gives two transactions differing in their change
address; only one of them can confirm, since both spend the same coins.

Not defended: a wrong destination. koinu will faithfully sign a spend to an
address you did not mean to type.

## The code

Every parser that reads bytes chosen by a peer has a fuzz target: transactions,
psbts, p2p frames, headers messages, blocks and compact filters. CI runs the
suite on linux x86_64 under gcc and clang, on linux i386, and on macos arm64,
then the sanitizers and the fuzzers.

Not done: an external security review. Everything here is self-assessed.
