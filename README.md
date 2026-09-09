# koinu

a dogecoin wallet in c, built from the crypto up. secp256k1 is the only
submodule; everything else it needs cryptographically lives in crypto/, either
vendored from a named upstream at a named commit or written here, and frozen.

## building

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
    kw send --tx @tx.hex --node NODE

the fee defaults to the peer's advertised relay floor, captured during scan;
--feerate sets a rate and --fee an exact amount. change below the dust limit
goes to the fee instead of an output.

    kw height   --headers h                  the tip height and hash
    kw outpoint --watch ADDR --outpoint TXID:VOUT --since HEIGHT
    kw sweep    --wif @k --to DEST           spend an external key's balance
    kw cosign   --tx HEX --redeem HEX --wif @k

outpoint answers whether a funding output is confirmed, to what depth, and
whether it has been spent, which is what a payment channel or a merchant needs
before it trusts a deposit. --since bounds the search to a height range so a
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

filters are checked against the peer's committed filter-header chain, and the
verified tip is kept beside the cache so a later delta sync has to connect to
it. --headers and --filters name caches that make a second run resume from the
stored tip instead of starting over.

    kw height --peers 24 --headers h

--peers downloads the checkpointed range of the header chain over that many
connections at once, splitting it at the chainparams anchors and verifying each
segment links internally and ends on its anchor. with no --node the peers come
from the dns seeds, and connections migrate to whichever ones prove fastest. a
cold mainnet header sync takes about two minutes.

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

a resident daemon for callers that need an answer in milliseconds rather than
seconds. it holds the header chain and the peer connection open, delta-syncs on
each request, and answers over a unix socket.

    kwd --node NODE --headers h --filters f --socket /run/kwd.sock
    kw outpoint --daemon /run/kwd.sock --watch ADDR --outpoint TXID:VOUT --since H
