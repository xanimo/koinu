# Threat model

What koinu defends against, what it does not, and what it takes on trust. This
is the document the README deliberately does not try to be.

## The boundary, in one place

Read this part if you read nothing else.

A compromised kwd cannot sign. It holds no keys, opens no keystore, and answers
one question about one outpoint; the worst it can do is lie about a confirmation,
which is why anything taking payment on a confirmation should run its own node and
pass `--node` more than once.

A compromised machine running kw can sign. The seed is on that machine and
decrypts there, so a program running as your user while kw runs can take it. No
wallet can be honest and claim otherwise. What koinu does is narrow the window:
the seed is sealed at rest, mlock'd while in use, wiped after, never in argv, and
the process that holds it never opens a socket. Key derivation is the one window
where passphrase-derived bytes can reach swap, and the section below says why.

koinu cannot save you from approving a payment you meant to approve. It decodes
what it is about to broadcast and makes you confirm it, and it refuses a few
shapes that are almost always mistakes, but a correct signature over a
transaction you read and accepted is not something a wallet can undo.

If you lose the seed and the wallet file, nobody can recover it. Not you, not us,
not a service. The keystore holds the 64-byte seed, not the words, and the words
cannot be derived back from it: `kw` has no export, and there is no account, no
login, no recovery address and nothing of yours on any machine but your own. That
is the point of the thing, and it is also the way it bites. `kw backup split`
spreads that risk over several shares rather than removing it, and a threshold
of them is still the wallet.

What it will not grow: server-side recovery, a login, telemetry, or any
convenience that needs the key process to talk to the network.

## Keys

Signing and broadcasting are already separate programs, so the machine that
holds the seed need never have a network interface. `kw sign` writes a
transaction to a file, something else carries the file across, and `kw send`
decodes and broadcasts it. `kw export xpub` prints the account public key for
the watching side, and `kw scan --xpub` tracks the wallet with no keystore, no
passphrase and no secret in the process: it derives every address under
m/44'/coin'/account' and no private key, because change and index are unhardened
and a public parent can walk them.

What the xpub costs is worth stating. It is not a secret in the way the seed is,
and it is not public either: whoever holds it sees every address the account will
ever use, before and after, and can tie them to each other. It cannot spend.

What the file handoff does not protect against is a signer that shows one thing
and signs another, which is why `kw sign` decodes the transaction it produced and
reports from those bytes rather than from the request that built them, and why
`kw send` decodes again before broadcasting. Both ends read the same
serialization; neither trusts the summary that came with it.

`kw backup verify` answers whether a phrase restores a wallet without putting the
two in the same place: it derives the seed the typed words give, opens the
keystore, and compares them in constant time, printing neither. A mismatch exits
3. With no `--keystore` it prints the master fingerprint and first address, so a
paper backup can be checked years later against an address already known, on a
machine that holds no wallet at all. Checking a backup used to mean restoring it
somewhere, which is how checking one becomes the thing that loses it.

`kw backup split` turns the seed into SLIP-39 shares and `kw backup combine`
turns a threshold of them back into a keystore, which separates the two numbers
a single written phrase conflates: one copy is lost to one fire and two copies
are stolen from either. With a threshold, losing the wallet takes more than the
count minus the threshold and stealing it takes the threshold, set apart from
each other. What is split is the 64-byte seed, which is what SLIP-39 names as
the master secret, so a threshold restores the same wallet anywhere the standard
is implemented. The shares go to stdout rather than to files, through write(2)
for the reason the mnemonic does.

Each share is useless alone and this is arithmetic rather than a claim: below
the threshold the shared polynomial is undetermined and every secret of that
length remains equally possible. What it does leak is the backup's shape, since
a share names its own group, its thresholds and the group count in clear.

Combine refuses a set that is not exactly a threshold rather than working with
a spare, because a set that reconstructs with one share left over does not say
what it reconstructed. It also seals a keystore rather than printing the seed,
which is the same rule the mnemonic follows: there is no export. The cost is
that checking a set of shares means writing a keystore somewhere, so the check
is to point it at a scratch path and compare the fingerprint.

`--backup-passphrase` is a third secret, separate from the one sealing the
keystore and from `--seed-passphrase`, and it has the same shape of hazard: a
wrong one combines to a different wallet rather than failing, since SLIP-39 has
nothing to check it against by design.

`--format codex32` writes the same split as BIP-93 strings instead, and what
that changes is who can check the backup. The checksum is a BCH code over
GF(32) and the Shamir arithmetic is over the same field, both small enough to
compute with a pen and a printed table, so a share can be verified and a lost
one recomputed without trusting the machine that reads it. Against SLIP-39 it
gives up the passphrase, the digest over the reconstructed secret, and the
two-level grouping: one flat threshold, no second secret, and a set of shares
that are individually valid still reconstructs whatever polynomial they
describe. Nothing in the format says that is the seed it came from, so the
fingerprint is the check, which is why split prints one and combine prints the
first address.

What a single codex32 share leaks is its own threshold, identifier and index in
clear, which is the shape of the backup rather than any of the seed. Below the
threshold the payload is undetermined in the same way SLIP-39's is.

A BIP39 passphrase, `--seed-passphrase` on new and restore, goes into the seed
rather than into the keystore: the words alone then restore a different wallet,
so a phrase recovered from a drawer does not spend. What it costs is that there
is nothing to check it against. Every passphrase yields a valid wallet, so a
wrong one restores an empty one rather than reporting a mistake, and a forgotten
one is as final as a lost phrase. The first address printed at restore is the
only check: compare it against one you have seen before.

The seed is the only secret. It lives sealed in the keystore under argon2id and
chacha20-poly1305, and in memory only for as long as a command needs it, mlock'd
and wiped after. The mnemonic is printed once at creation and never stored, so a
stolen keystore without its passphrase yields nothing and a lost mnemonic cannot
be recovered from the keystore.

What is mlock'd is the seed, the master and child BIP32 keys derived from it,
the key the keystore derives from a passphrase, a WIF decoded for a sweep or a
co-signature, and the buffer a passphrase or mnemonic is read into. The master
xprv is the seed in another encoding, so calling the seed the only secret and
locking only the seed was a distinction without a difference. Those locks are counted per page, because mlock is not
and two of them share a page often: the derived key sits a frame below the seed
it decrypts. The derivation's own working memory is not locked. argon2id
allocates m_cost_kib of passphrase-derived state itself, up to the 1 GiB a
keystore header may ask for, and bip39 builds "mnemonic" plus the passphrase on
the heap for the length of 2048 PBKDF2 rounds. Both are wiped before they are
freed, so nothing is left behind in the process, but neither is pinned and
either may be paged out while the derivation runs. Locking a gibibyte would fail
under the usual RLIMIT_MEMLOCK, so this is stated rather than fixed: on a machine
with swap enabled and under memory pressure, key derivation is the window where
passphrase-derived bytes can reach disk.

Passphrases, mnemonics and private keys are read from a file, from stdin, or
from a no-echo prompt. A bare value on the command line is refused, because argv
is readable by any process on the machine.

kw, kwui and kwd set RLIMIT_CORE to zero and clear PR_SET_DUMPABLE before
anything reads a secret, because mlock keeps a secret out of swap and says
nothing about a core file: a SIGQUIT at the passphrase prompt put a mnemonic the
user had not seen yet into one, and systemd-coredump, apport and a ci artifact
collector all keep what they are given. The mnemonic is written with write(2)
rather than printf for the same reason reading one avoids stdio: a buffer malloc
hands out once and nothing wipes outlives every forget in the process.

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
hashing the whole chain: it ignores a header cache and syncs again, because the
cache keeps 80-byte headers and no merged-mining proofs and the work above the
merge-mining start lives in the parent block a proof carries. It also gives up the
parallel fill, which writes that range without the proofs for the same reason. A header that fails stops the sync rather than being
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
cfheaders rather than derived from blocks. Too few is currently none: of 48 peers
from the dns seeds, 47 answered and none advertised bip158, so this section
describes a backend that needs a node you run yourself.

A header's timestamp has to be newer than the median of the eleven before it and
no more than two hours ahead of local time, which is what stops a chain writing
its own difficulty: the retarget rule is derived from those timestamps, and
without the bounds a run of them claiming the maximum easing walks the target to
powLimit, after which a header costs nothing. With them the cheapest fake run
costs real work, though less than the blocks it pretends to be: about 2.7 blocks
for six confirmations either way, which is the number to budget against rather
than six.

A peer cannot invent a confirmation above the newest anchor, since it would have to
mine the headers and the body has to hash to the header. It can withhold one, and a
fork it serves is weighed against what other peers serve, so withholding costs it
the comparison unless every peer reached is in on it. For anything accepting
payment on the strength of a confirmation, prefer a node you control, which is what
`--node` is for, and pass it more than once.

Over Tor each connection offers a fresh random username and password, which is
what tor keys a circuit on, so kwd's resident peers, the parallel download's
workers and the three chains being weighed do not share one exit. With no
credentials offered they could, and that exit would see plaintext p2p for every
peer the wallet treats as independent and be able to withhold from all of them.
`make net_tor` opens three connections through a local daemon and reads
`circuit-status` off the control port, so the circuits are counted rather than
assumed.

Peer choice is the weakest part of all of this. Without `--node` the mainnet
seeds are two hostnames in one domain, so whoever controls them, or the resolver
path to them, picks every peer the parallel sync and the three-way work
comparison use, and the comparison's assumption that the peers are independent
does not hold. Anchors and the work checks bound that to eclipse and censorship
rather than forged history below an anchor, but above the newest anchor a chosen
peer set is the whole input. Pass `--node` more than once, with nodes you chose,
for anything that accepts payment.

## Transactions

Signing is deterministic (RFC 6979) and low-S, so a repeated signature is
identical and a nonce is never reused. The signer is byte-exact against
libdogecoin's on the p2pkh vectors.

Every OP_CODESEPARATOR is removed from the scriptCode before it is hashed, as
consensus does, so a signature over a script containing one is the signature a
node checks rather than one that verifies only locally.

`kw psbt` and `kw cosign` verify every counterparty signature against the sighash
before assembling a spend, and neither signs a script that does not name the
signing key: a script spending with one key is not a script to co-sign on
request, which is how a p2pkh scriptPubKey passed off as a redeem script turned a
cosignature into a spend of the signer's own coin. psbt sign also binds the
script to the coin, since a psbt carries it; cosign can only do that when
`--utxo` is given, and without it the key check is the whole of the binding, so a signature that would fail on chain is refused
locally rather than broadcast. A psbt carrying fields koinu cannot represent is
refused rather than parsed with those fields dropped, since a combiner that
silently discards what it does not understand loses the other party's data.

The journal, the utxo set and its scan metadata are 0600 and written through a
temp file and a rename, since all three name amounts, heights and addresses. The
utxo set carries its own count, so a file cut short refuses to load rather than
loading as a smaller balance.

A coinbase output is tracked as one and is not spendable until
KOINU_COINBASE_MATURITY confirmations: outpoint says "unspent but immature" and
exits 5 rather than 0, and signing leaves it out of selection. An orphaned block
erases such an output rather than returning it to a mempool, so a confirmation on
one is worth less than a confirmation on a payment.

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
