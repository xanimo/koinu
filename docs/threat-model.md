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

### Verified

Every header past the last checkpoint compiled into chainparams has its work
checked. Its nBits must be the value the retarget rule derives from the headers
before it rather than a value it claims, and its hash must be under that target. A
merged-mined header is checked through its AuxPoW proof, so the parent block's work
is what has to be there. `scan`, `outpoint`, `sweep`, `height` and `cfcheckpoints`
sync through one function, so none of them checks less than the others.
`--validate-pow` moves the floor to height 1 and trusts no anchor, at the cost of
hashing the whole chain. A header that fails stops the sync rather than being
skipped.

A block body is refused unless its transactions hash to the header's merkle root,
and a tree level with an equal adjacent pair is refused with it, since an odd level
repeats its last node and the root cannot then say which transaction list it came
from (CVE-2012-2459).

Below the last anchor the parallel download verifies that each segment links
internally and ends on a hash compiled into chainparams, and no work is checked
there. A block hash names one chain where work only proves energy was spent on
some chain. The anchors are only as good as the release that carries them.

A command that syncs headers opens up to three connections, asks each where its
chain leaves the one already held, syncs each fork and keeps the heaviest, measured
from the newest anchor. The chain already cached is one of the candidates, so a
peer has to beat it rather than differ from it. Each candidate's work is checked by
its own validator pool, so one peer's bad header does not discard another's chain.
A fork below an anchor is refused rather than weighed.

### Not verified

Work is compared among the peers reached, not against the chain with the most work
in existence. Three peers that agree can all be wrong, by collusion or by being one
node behind three addresses, and a wallet given one `--node` compares nothing and
says so.

A reorganisation deeper than the newest anchor is refused rather than followed.
More than 200000 headers above the newest anchor and the comparison is skipped as
too expensive to buffer, with one peer used instead. A release whose anchors are
stale defends less than a current one.

Every filter is checked against that peer's cfheaders chain and the verified tip is
pinned, so a peer cannot rewrite history it already served. The chain is also
checked against the filter-header anchors in chainparams, every 100000 blocks to
height 6300000, so a peer serving a different filter set is caught at the first
anchor it crosses. Above the last anchor the base is still the peer's word. Compact
filters are served by too few nodes to compare peers against each other, so this is
an anchor table rather than a quorum, and the anchors were generated from one node's
cfheaders rather than derived from blocks.

A peer cannot invent a confirmation above the newest anchor, since it would have to
mine the headers and the body has to hash to the header. It can withhold one, and a
fork it serves is weighed against what other peers serve, so withholding costs it
the comparison unless every peer reached is in on it. For anything accepting
payment on the strength of a confirmation, prefer a node you control, which is what
`--node` is for, and pass it more than once.

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
