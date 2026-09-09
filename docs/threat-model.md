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

### Not verified

**Proof of work is not checked.** Dogecoin is merged-mined, and koinu skips the
AuxPoW blob rather than validating it. Nothing in koinu confirms that the chain
it was served represents accumulated work.

**The checkpointed header range is validated by anchor linkage.** The parallel
download verifies that each segment links internally and ends on a hash compiled
into chainparams. That makes a served chain match a known one; it does not make
it the most-work chain, and the anchors are only as good as the release that
carries them.

**Filter commitments are trust-on-first-use, against one peer.** Every filter is
checked against that peer's cfheaders chain and the verified tip is pinned, so a
peer cannot rewrite history it already served. The chain's base is taken from
whichever peer answered first, and there is no cross-peer comparison, so a peer
that lies consistently from the start is believed.

The practical consequence: a peer that can serve a consistent false history can
convince koinu a transaction confirmed when it did not. For a wallet spending
its own coins this is a nuisance. For anything accepting payment on the strength
of a confirmation, prefer a node you control, which is what `--node` is for.

## Transactions

Signing is deterministic (RFC 6979) and low-S, so a repeated signature is
identical and a nonce is never reused. The signer is byte-exact against
libdogecoin's on the p2pkh vectors.

`kw psbt` and `kw cosign` verify every counterparty signature against the sighash
before assembling a spend, so a signature that would fail on chain is refused
locally rather than broadcast. A psbt carrying fields koinu cannot represent is
refused rather than parsed with those fields dropped, since a combiner that
silently discards what it does not understand loses the other party's data.

Not defended: a wrong destination. koinu will faithfully sign a spend to an
address you did not mean to type.

## The code

Every parser that reads bytes chosen by a peer has a fuzz target: transactions,
psbts, p2p frames, headers messages, blocks and compact filters. CI runs the
suite on linux x86_64 under gcc and clang, on linux i386, and on macos arm64,
then the sanitizers and the fuzzers.

Not done: an external security review. Everything here is self-assessed.
