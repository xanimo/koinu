#!/usr/bin/env bash
# kw smoke test: create a wallet, re-derive its address, and confirm the
# passphrase and clobber protections. Uses regtest so addresses start m/n.
set -eu
cd "$(dirname "$0")/.."

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
printf 'a test passphrase\n' > "$WORK/pass"

OUT=$(./kw --regtest new --keystore "$WORK/ks" --passphrase "@$WORK/pass" --words 12)
echo "$OUT"
ADDR1=$(echo "$OUT" | awk '/first address/{print $3}')
[ -n "$ADDR1" ] || { echo "FAIL: no address printed" >&2; exit 1; }
case "$ADDR1" in m*|n*) ;; *) echo "FAIL: regtest address prefix: $ADDR1" >&2; exit 1;; esac

ADDR2=$(./kw --regtest address --keystore "$WORK/ks" --passphrase "@$WORK/pass")
[ "$ADDR1" = "$ADDR2" ] || { echo "FAIL: address not reproducible ($ADDR1 vs $ADDR2)" >&2; exit 1; }

# a different index gives a different address
ADDR3=$(./kw --regtest address --keystore "$WORK/ks" --passphrase "@$WORK/pass" --index 1)
[ "$ADDR1" != "$ADDR3" ] || { echo "FAIL: index 1 matched index 0" >&2; exit 1; }

# wrong passphrase must fail
printf 'wrong\n' > "$WORK/bad"
if ./kw --regtest address --keystore "$WORK/ks" --passphrase "@$WORK/bad" >/dev/null 2>&1; then
    echo "FAIL: wrong passphrase opened the keystore" >&2; exit 1
fi

# new must refuse to overwrite an existing keystore
if ./kw --regtest new --keystore "$WORK/ks" --passphrase "@$WORK/pass" >/dev/null 2>&1; then
    echo "FAIL: new clobbered an existing keystore" >&2; exit 1
fi

# sign: spend a fixed outpoint to our own address, deterministic and well-formed.
# --change pins the change address, since without it the second signature rotates
# past the first and the transactions differ by design.
IN="0000000000000000000000000000000000000000000000000000000000000001:0:10.0:0"
RAW1=$(./kw --regtest sign --keystore "$WORK/ks" --passphrase "@$WORK/pass" \
       --input "$IN" --to "$ADDR1:8.5" --fee 0.001 --change-to "$ADDR1" | awk '/^raw/{print $2}')
[ -n "$RAW1" ] || { echo "FAIL: sign produced no raw tx" >&2; exit 1; }
case "$RAW1" in 01000000*00000000) ;; *) echo "FAIL: raw tx not well-formed" >&2; exit 1;; esac
RAW2=$(./kw --regtest sign --keystore "$WORK/ks" --passphrase "@$WORK/pass" \
       --input "$IN" --to "$ADDR1:8.5" --fee 0.001 --change-to "$ADDR1" | awk '/^raw/{print $2}')
[ "$RAW1" = "$RAW2" ] || { echo "FAIL: sign not deterministic" >&2; exit 1; }
# a different amount must change the transaction
RAW3=$(./kw --regtest sign --keystore "$WORK/ks" --passphrase "@$WORK/pass" \
       --input "$IN" --to "$ADDR1:8.0" --fee 0.001 --change-to "$ADDR1" | awk '/^raw/{print $2}')
[ "$RAW1" != "$RAW3" ] || { echo "FAIL: amount change did not alter the tx" >&2; exit 1; }

# signing records the spend, and signing the same spend twice records it once:
# three signs above, two of them identical, so two entries
J="$WORK/ks.utxos.journal"
[ -f "$J" ] || { echo "FAIL: sign wrote no journal at $J" >&2; exit 1; }
NJ=$(awk 'END{print NR}' "$J")
[ "$NJ" = "2" ] || { echo "FAIL: journal has $NJ entries, want 2" >&2; cat "$J" >&2; exit 1; }
awk '$2 != "out" { exit 1 }' "$J" || { echo "FAIL: a signed spend is not an out entry" >&2; exit 1; }
grep -q "$ADDR1" "$J" || { echo "FAIL: the journal does not name the destination" >&2; exit 1; }

# change rotates: with a utxo already paid to change index 0, the next spend must
# use index 1 rather than paying the same address twice
SPK0=$(./kw --regtest address --keystore "$WORK/ks" --passphrase "@$WORK/pass" --change --index 0 --spk)
[ -n "$SPK0" ] || { echo "FAIL: no change scriptPubKey" >&2; exit 1; }
# built rather than written: since v2 an amount in the set has to be the one its
# transaction carries, so there is no hand-writing a value any more
./test/mkutxos "$WORK/ks.utxos" "$SPK0" 1000000000 1 \
    || { echo "FAIL: mkutxos" >&2; exit 1; }
CH=$(./kw --regtest sign --keystore "$WORK/ks" --passphrase "@$WORK/pass" \
     --input "$IN" --to "$ADDR1:8.5" --fee 0.001 | awk '/^change/{print $2}')
[ "$CH" = "m/44'/1'/0'/1/1" ] || { echo "FAIL: change went to $CH, want index 1" >&2; exit 1; }
# two spends in a row with no scan between them must not share a change address.
# only kw scan rewrites the utxo file, so this is the case a utxo-set-only rule
# gets wrong, and it is the ordinary one: send, then send again.
rm -f "$WORK/ks.utxos" "$WORK/ks.utxos.journal"
CA=$(./kw --regtest sign --keystore "$WORK/ks" --passphrase "@$WORK/pass" \
     --input "$IN" --to "$ADDR1:8.5" --fee 0.001 | awk '/^change/{print $2}')
CB=$(./kw --regtest sign --keystore "$WORK/ks" --passphrase "@$WORK/pass" \
     --input "$IN" --to "$ADDR1:8.4" --fee 0.001 | awk '/^change/{print $2}')
CC=$(./kw --regtest sign --keystore "$WORK/ks" --passphrase "@$WORK/pass" \
     --input "$IN" --to "$ADDR1:8.3" --fee 0.001 | awk '/^change/{print $2}')
[ "$CA" = "m/44'/1'/0'/1/0" ] || { echo "FAIL: first spend used $CA" >&2; exit 1; }
[ "$CB" = "m/44'/1'/0'/1/1" ] || { echo "FAIL: second spend used $CB, want index 1" >&2; exit 1; }
[ "$CC" = "m/44'/1'/0'/1/2" ] || { echo "FAIL: third spend used $CC, want index 2" >&2; exit 1; }
rm -f "$WORK/ks.utxos.journal"

# a change index whose coins have since been spent must stay used: the utxo set
# has forgotten it, so this is the journal's answer, not the utxo set's
./test/mkutxos "$WORK/ks.utxos" "$SPK0" 1000000000 1 \
    || { echo "FAIL: mkutxos" >&2; exit 1; }
CADDR1=$(./kw --regtest address --keystore "$WORK/ks" --passphrase "@$WORK/pass" --change --index 1)
[ -n "$CADDR1" ] || { echo "FAIL: no change address at index 1" >&2; exit 1; }
echo "1700000000 in 0000000000000000000000000000000000000000000000000000000000000003 1 5 100000000 0 $CADDR1" \
    >> "$WORK/ks.utxos.journal"
chmod 600 "$WORK/ks.utxos.journal"     # written here by the shell, not by kw
CH2=$(./kw --regtest sign --keystore "$WORK/ks" --passphrase "@$WORK/pass" \
      --input "$IN" --to "$ADDR1:8.5" --fee 0.001 | awk '/^change/{print $2}')
[ "$CH2" = "m/44'/1'/0'/1/2" ] || { echo "FAIL: change went to $CH2, want index 2" >&2; exit 1; }

rm -f "$WORK/ks.utxos"

# a non-interactive broadcast without --yes exits 2, not 1: a caller reads the code
# and "you forgot a flag" is not the same answer as "the node rejected it"
set +e
echo "$RAW1" | ./kw --regtest send --tx - --node 127.0.0.1 >/dev/null 2>&1
SRC=$?
set -e
[ "$SRC" = "2" ] || { echo "FAIL: send without --yes exited $SRC, want 2" >&2; exit 1; }

# more --input than a transaction may carry is an error, not a silent drop: a
# dropped input funds less than was asked for and the change output absorbs it
MANY=""
i=1
while [ $i -le 40 ]; do
    MANY="$MANY --input $(printf '00000000000000000000000000000000000000000000000000000000000000%02x' $i):0:1.0:0"
    i=$((i + 1))
done
if ./kw --regtest sign --keystore "$WORK/ks" --passphrase "@$WORK/pass" \
   $MANY --to "$ADDR1:1.0" --fee 0.001 >/dev/null 2>&1; then
    echo "FAIL: signed with more inputs than the limit" >&2; exit 1
fi
CH0=$(./kw --regtest sign --keystore "$WORK/ks" --passphrase "@$WORK/pass" \
      --input "$IN" --to "$ADDR1:8.5" --fee 0.001 | awk '/^change/{print $2}')
[ "$CH0" = "m/44'/1'/0'/1/0" ] || { echo "FAIL: change went to $CH0 with nothing spent, want index 0" >&2; exit 1; }
# it names amounts and addresses, so it is not world-readable
case $(ls -l "$J") in
    -rw-------*) ;;
    *) echo "FAIL: journal is $(ls -l "$J" | cut -c1-10), want -rw-------" >&2; exit 1;;
esac

# sign --raw puts the transaction alone on stdout, so the output goes straight
# into send. The readback a person reads moves to stderr rather than being
# suppressed: skipping it should take --yes, not a stdout redirect.
RAWONLY=$(./kw --regtest sign --keystore "$WORK/ks" --passphrase "@$WORK/pass" \
           --input "$IN" --to "$ADDR1:8.5" --fee 0.001 --change-to "$ADDR1" --raw 2>/dev/null)
case "$RAWONLY" in 01000000*00000000) ;; *) echo "FAIL: --raw did not print a bare transaction" >&2; exit 1;; esac
[ "$(printf '%s\n' "$RAWONLY" | wc -l)" -eq 1 ] \
    || { echo "FAIL: --raw printed more than the transaction" >&2; exit 1; }
./kw --regtest sign --keystore "$WORK/ks" --passphrase "@$WORK/pass" \
     --input "$IN" --to "$ADDR1:8.5" --fee 0.001 --change-to "$ADDR1" --raw 2>&1 >/dev/null \
    | grep -q "^fee" || { echo "FAIL: --raw lost the readback instead of moving it" >&2; exit 1; }
# and the default still carries both, which the assertions above rely on
./kw --regtest sign --keystore "$WORK/ks" --passphrase "@$WORK/pass" \
     --input "$IN" --to "$ADDR1:8.5" --fee 0.001 --change-to "$ADDR1" 2>/dev/null \
    | grep -q "^raw   " || { echo "FAIL: the default output changed" >&2; exit 1; }
# the pipeline itself: send has to decode what sign handed it
./kw --regtest sign --keystore "$WORK/ks" --passphrase "@$WORK/pass" \
     --input "$IN" --to "$ADDR1:8.5" --fee 0.001 --change-to "$ADDR1" --raw 2>/dev/null \
  | ./kw --regtest send --tx - --node 127.0.0.1 --port 1 --yes 2>&1 \
  | grep -q "^txid" || { echo "FAIL: send could not read what sign piped it" >&2; exit 1; }

# send decodes what it is about to broadcast rather than pushing opaque hex. The
# destination it prints has to be the one that was signed for, since the whole point
# is catching a transaction that pays somewhere else.
echo "$RAW1" > "$WORK/tx.hex"
SEND="./kw --regtest send --tx @$WORK/tx.hex --node 127.0.0.1 --port 1"
SHOWN=$($SEND 2>/dev/null | awk '/^pays/{print $NF; exit}')
[ "$SHOWN" = "$ADDR1" ] || { echo "FAIL: send shows $SHOWN, signed for $ADDR1" >&2; exit 1; }
$SEND 2>/dev/null | grep -q "^spends  0000000000000000000000000000000000000000000000000000000000000001:0" \
    || { echo "FAIL: send does not name the outpoint it spends" >&2; exit 1; }

# without a way to confirm, it refuses rather than broadcasting anyway
$SEND >/dev/null 2>"$WORK/err" || true          # refusing is the pass here
grep -q "pass --yes" "$WORK/err" \
    || { echo "FAIL: send did not refuse an unconfirmed broadcast" >&2; cat "$WORK/err" >&2; exit 1; }

# with --yes it gets as far as the network, which is refused on port 1
$SEND --yes >/dev/null 2>"$WORK/err2" || true   # the connect is meant to fail
grep -q "connect to 127.0.0.1:1 failed" "$WORK/err2" \
    || { echo "FAIL: --yes did not reach the broadcast" >&2; cat "$WORK/err2" >&2; exit 1; }

# and bytes that are not a transaction are refused before any of that
echo deadbeef > "$WORK/junk.hex"
./kw --regtest send --tx "@$WORK/junk.hex" --node 127.0.0.1 --port 1 --yes >/dev/null 2>"$WORK/err3" || true
grep -q "does not decode as a transaction" "$WORK/err3" \
    || { echo "FAIL: send accepted bytes that are not a transaction" >&2; cat "$WORK/err3" >&2; exit 1; }
# insufficient inputs must fail
if ./kw --regtest sign --keystore "$WORK/ks" --passphrase "@$WORK/pass" \
       --input "$IN" --to "$ADDR1:20.0" --fee 0.001 >/dev/null 2>&1; then
    echo "FAIL: signed a spend the inputs cannot cover" >&2; exit 1
fi
# an absurd fee must be refused: this tx is 226 bytes, so the limit is 0.226 DOGE
if ./kw --regtest sign --keystore "$WORK/ks" --passphrase "@$WORK/pass" \
       --input "$IN" --to "$ADDR1:1.0" --fee 5.0 >/dev/null 2>&1; then
    echo "FAIL: signed a spend paying a 5 DOGE fee" >&2; exit 1
fi
# --feerate reaches the same limit, since the fee is rate times size. 2 DOGE/kB
# over 226 bytes is 0.452, which the inputs still cover, so this is the fee
# check refusing it and not the balance check
if ./kw --regtest sign --keystore "$WORK/ks" --passphrase "@$WORK/pass" \
       --input "$IN" --to "$ADDR1:1.0" --feerate 2.0 >/dev/null 2>&1; then
    echo "FAIL: signed a spend at a 2 DOGE/kB rate" >&2; exit 1
fi
# --maxfee raises it, and is itself enforced
./kw --regtest sign --keystore "$WORK/ks" --passphrase "@$WORK/pass" \
     --input "$IN" --to "$ADDR1:1.0" --fee 5.0 --maxfee 6.0 >/dev/null \
     || { echo "FAIL: --maxfee 6.0 did not permit a 5 DOGE fee" >&2; exit 1; }
if ./kw --regtest sign --keystore "$WORK/ks" --passphrase "@$WORK/pass" \
       --input "$IN" --to "$ADDR1:1.0" --fee 5.0 --maxfee 4.0 >/dev/null 2>&1; then
    echo "FAIL: paid a 5 DOGE fee under --maxfee 4.0" >&2; exit 1
fi
# change dropped for dust is folded into the fee, so the limit must judge what
# is paid rather than --fee. 0.19 is under the limit on its own (it signs with a
# change output below), but leaving 0.009 of dust change pushes the paid fee to
# 0.199 against a 0.192 limit for the resulting one-output tx
./kw --regtest sign --keystore "$WORK/ks" --passphrase "@$WORK/pass" \
     --input "$IN" --to "$ADDR1:9.0" --fee 0.19 >/dev/null \
     || { echo "FAIL: 0.19 fee refused with a change output" >&2; exit 1; }
if ./kw --regtest sign --keystore "$WORK/ks" --passphrase "@$WORK/pass" \
       --input "$IN" --to "$ADDR1:9.801" --fee 0.19 >/dev/null 2>&1; then
    echo "FAIL: dust change folded into the fee escaped the limit" >&2; exit 1
fi

# A change output dropped for dust takes 34 bytes off the estimate, which can
# lift the change back over the dust limit. The transaction then carried two
# outputs and a one-output fee, under the rate it was built from.
OUTF=$(./kw --regtest sign --keystore "$WORK/ks" --passphrase "@$WORK/pass" \
     --input "$IN" --to "$ADDR1:9.9898" 2>/dev/null)
FEEK=$(echo "$OUTF" | awk '/^fee/{print $2}')
SIZEB=$(echo "$OUTF" | awk '/^fee/{print $4}')
MINF=$(( (SIZEB * 100000 + 999) / 1000 ))
if [ "$FEEK" -lt "$MINF" ]; then
    echo "FAIL: $FEEK koinu for $SIZEB bytes is under the relay floor of $MINF" >&2; exit 1
fi

# an amount over MAX_MONEY is refused rather than wrapped through send + fee
if ./kw --regtest sign --keystore "$WORK/ks" --passphrase "@$WORK/pass" \
       --input "$IN" --to "$ADDR1:184467440737.09551615" >/dev/null 2>&1; then
    echo "FAIL: signed an amount that does not fit the money supply" >&2; exit 1
fi

# one outpoint, one spelling: vout went through strtoul with no end pointer and no
# range, so 4294967297, "1junk" and " +1" all answered for vout 1 and a backend
# deduplicating on the string it sent would credit one payment several times.
for BAD in 4294967297 1junk -1 00; do
    if ./kw --regtest outpoint --watch "$ADDR1" --node 127.0.0.1 --port 1 --since 1 \
           --outpoint "0000000000000000000000000000000000000000000000000000000000000001:$BAD" \
           2>&1 | grep -q "^kw: --outpoint vout wants"; then :; else
        echo "FAIL: vout \"$BAD\" was not refused" >&2; exit 1
    fi
done
# and the shapes strtok folded away: an empty vout field, a second colon, and a
# txid with no vout at all. Each answered for vout 0 before.
OPTX=0000000000000000000000000000000000000000000000000000000000000001
for BAD in "$OPTX::0" "$OPTX:0:" "$OPTX:0:junk" "$OPTX"; do
    OUT=$(./kw --regtest outpoint --watch "$ADDR1" --node 127.0.0.1 --port 1 --since 1 \
               --outpoint "$BAD" 2>&1 | head -1)
    case "$OUT" in "kw: --outpoint"*) ;; *)
        echo "FAIL: \"$BAD\" was taken as an outpoint: $OUT" >&2; exit 1;; esac
done
# while the one spelling it does take gets past the parse
OUT=$(./kw --regtest outpoint --watch "$ADDR1" --node 127.0.0.1 --port 1 --since 1 \
           --outpoint "$OPTX:0" 2>&1 | head -1)
case "$OUT" in "kw: --outpoint"*)
    echo "FAIL: the canonical spelling was refused: $OUT" >&2; exit 1;; esac

# --input split with strtok, which folds an empty field and stops at the fourth,
# so "T::1:5:0" and "T:1:5:0:extra" both signed.
INTX=1111111111111111111111111111111111111111111111111111111111111111
for BAD in "$INTX::1:5:0" "$INTX:1:5:0:extra" "$INTX:1:5" "$INTX:1::0"; do
    if ./kw --regtest sign --keystore "$WORK/ks" --passphrase "@$WORK/pass" \
           --input "$BAD" --to "$ADDR1:1" >/dev/null 2>&1; then
        echo "FAIL: --input \"$BAD\" was taken" >&2; exit 1
    fi
done

# each --input amount is bounded on its own, and the sum was not: nineteen
# inputs of ten billion DOGE wrapped the total and produced outputs the fee was
# computed against.
BIG=""
for i in $(seq 1 19); do
    BIG="$BIG --input 1111111111111111111111111111111111111111111111111111111111111111:$i:10000000000:0"
done
if ./kw --regtest sign --keystore "$WORK/ks" --passphrase "@$WORK/pass" $BIG \
       --to "$ADDR1:1000" >/dev/null 2>&1; then
    echo "FAIL: nineteen ten-billion-DOGE inputs signed" >&2; exit 1
fi

# the mnemonic is the only backup, so a write that fails must not leave a
# keystore behind: against /dev/full every write failed and kw still sealed one
# and exited 0.
if ./kw --regtest new --keystore "$WORK/ksfull" --passphrase "@$WORK/pass" > /dev/full 2>/dev/null; then
    echo "FAIL: kw new exited 0 with the mnemonic written nowhere" >&2; exit 1
fi
if [ -e "$WORK/ksfull" ]; then
    echo "FAIL: a keystore was sealed whose mnemonic was never shown" >&2; exit 1
fi

# kw backup verify answers "do these words restore this wallet" without putting
# the words and the wallet in the same place: it compares derived seeds in
# constant time and prints neither. Most coins lost to key handling are lost to
# a backup nobody checked, and checking one used to mean restoring it somewhere.
BK=$(./kw --regtest new --keystore "$WORK/bk.ks" --passphrase "@$WORK/pass" --words 24 \
      2>/dev/null | sed -n '2p' | tr -s ' ' | sed 's/^ *//;s/ *$//')
printf '%s\n' "$BK" > "$WORK/bkm"
./kw --regtest backup verify --keystore "$WORK/bk.ks" --passphrase "@$WORK/pass" \
     --mnemonic "@$WORK/bkm" >/dev/null 2>&1 \
    || { echo "FAIL: the right words did not verify" >&2; exit 1; }
# a different wallet's words must not verify, and must say so with its own code
OTHER=$(./kw --regtest new --keystore "$WORK/bk2.ks" --passphrase "@$WORK/pass" --words 24 \
         2>/dev/null | sed -n '2p' | tr -s ' ' | sed 's/^ *//;s/ *$//')
printf '%s\n' "$OTHER" > "$WORK/bkm2"
RCV=0
./kw --regtest backup verify --keystore "$WORK/bk.ks" --passphrase "@$WORK/pass" \
     --mnemonic "@$WORK/bkm2" >/dev/null 2>&1 || RCV=$?
[ "$RCV" = "3" ] || {
    echo "FAIL: another wallet's words verified, or exited $RCV and not 3" >&2; exit 1; }
# neither the words nor the seed may appear in the output
VOUT=$(./kw --regtest backup verify --keystore "$WORK/bk.ks" --passphrase "@$WORK/pass" \
        --mnemonic "@$WORK/bkm" 2>&1)
FIRSTWORD=$(printf '%s' "$BK" | cut -d' ' -f1)
case "$VOUT" in
    *"$FIRSTWORD"*) echo "FAIL: backup verify printed part of the mnemonic" >&2; exit 1;;
esac
# and with no keystore it reports what the words derive, for checking by hand
./kw --regtest backup verify --mnemonic "@$WORK/bkm" 2>/dev/null | grep -q "^fingerprint" \
    || { echo "FAIL: no fingerprint without a keystore" >&2; exit 1; }

# kw backup split/combine: a threshold of SLIP-39 shares restores the wallet and
# fewer of them restore nothing. The shares are checked by sealing a second
# keystore and comparing its first address, which is the check the help tells
# the user to make.
./kw --regtest backup split --keystore "$WORK/bk.ks" --passphrase "@$WORK/pass" \
     --groups 2of3 > "$WORK/sh.txt" 2>/dev/null \
    || { echo "FAIL: backup split failed" >&2; exit 1; }
# -eq rather than = throughout: BSD wc pads its count with spaces
NSH=$(grep -c '^  [0-9]  ' "$WORK/sh.txt")
[ "$NSH" -eq 3 ] || { echo "FAIL: split wrote $NSH shares, wanted 3" >&2; exit 1; }
# 59 words for a 64-byte seed
WORDS=$(sed -n 's/^  1  //p' "$WORK/sh.txt" | wc -w)
[ "$WORDS" -eq 59 ] || { echo "FAIL: a share is $WORDS words, wanted 59" >&2; exit 1; }
sed -n 's/^  [13]  //p' "$WORK/sh.txt" > "$WORK/sh.pick"
A_BK=$(./kw --regtest address --keystore "$WORK/bk.ks" --passphrase "@$WORK/pass")
A_SH=$(./kw --regtest backup combine --keystore "$WORK/sh.ks" --passphrase "@$WORK/pass" \
        --shares "@$WORK/sh.pick" 2>/dev/null | awk '/first address/{print $3}')
[ "$A_BK" = "$A_SH" ] || {
    echo "FAIL: two of three shares restored $A_SH and not $A_BK" >&2; exit 1; }
# one share is under the threshold, and the keystore must not be written
sed -n 's/^  1  //p' "$WORK/sh.txt" > "$WORK/sh.one"
if ./kw --regtest backup combine --keystore "$WORK/sh1.ks" --passphrase "@$WORK/pass" \
        --shares "@$WORK/sh.one" >/dev/null 2>&1; then
    echo "FAIL: one share of three combined" >&2; exit 1
fi
[ ! -e "$WORK/sh1.ks" ] || { echo "FAIL: a refused combine wrote a keystore" >&2; exit 1; }
# a backup passphrase makes a different wallet of the same shares, silently,
# which is the hazard the help states
printf 'a backup passphrase\n' > "$WORK/bpass"
A_BP=$(./kw --regtest backup combine --keystore "$WORK/shbp.ks" --passphrase "@$WORK/pass" \
        --shares "@$WORK/sh.pick" --backup-passphrase "@$WORK/bpass" 2>/dev/null \
        | awk '/first address/{print $3}')
[ -n "$A_BP" ] || { echo "FAIL: combine with a backup passphrase failed" >&2; exit 1; }
[ "$A_BP" != "$A_SH" ] || {
    echo "FAIL: a backup passphrase restored the same wallet" >&2; exit 1; }
# and the shares it makes do restore that wallet
./kw --regtest backup split --keystore "$WORK/shbp.ks" --passphrase "@$WORK/pass" \
     --groups 1of1,2of3 --group-threshold 2 --backup-passphrase "@$WORK/bpass" \
     > "$WORK/sh2.txt" 2>/dev/null \
    || { echo "FAIL: split across two groups failed" >&2; exit 1; }
NSH2=$(grep -c '^  [0-9]  ' "$WORK/sh2.txt")
[ "$NSH2" -eq 4 ] || { echo "FAIL: two groups wrote $NSH2 shares, wanted 4" >&2; exit 1; }
sed -n 's/^  [0-9]  //p' "$WORK/sh2.txt" | sed -n '1p;2p;3p' > "$WORK/sh2.pick"
A_G=$(./kw --regtest backup combine --keystore "$WORK/sh2.ks" --passphrase "@$WORK/pass" \
       --shares "@$WORK/sh2.pick" --backup-passphrase "@$WORK/bpass" 2>/dev/null \
       | awk '/first address/{print $3}')
[ "$A_G" = "$A_BP" ] || {
    echo "FAIL: a group threshold restored $A_G and not $A_BP" >&2; exit 1; }
# one group of the two is under the group threshold
sed -n '1p' "$WORK/sh2.pick" > "$WORK/sh2.one"
if ./kw --regtest backup combine --keystore "$WORK/sh2b.ks" --passphrase "@$WORK/pass" \
        --shares "@$WORK/sh2.one" --backup-passphrase "@$WORK/bpass" >/dev/null 2>&1; then
    echo "FAIL: one group of two combined" >&2; exit 1
fi
# a share must not be a threshold in name only
if ./kw --regtest backup split --keystore "$WORK/bk.ks" --passphrase "@$WORK/pass" \
        --groups 1of3 >/dev/null 2>&1; then
    echo "FAIL: split accepted a 1-of-3 threshold" >&2; exit 1
fi

# --format codex32 is the same split as BIP-93 strings. combine reads the format
# off the shares rather than taking a flag that could disagree with the file.
./kw --regtest backup split --keystore "$WORK/bk.ks" --passphrase "@$WORK/pass" \
     --format codex32 --groups 3of5 --id kw00 > "$WORK/cx.txt" 2>/dev/null \
    || { echo "FAIL: codex32 split failed" >&2; exit 1; }
NCX=$(grep -c '^  [0-9]  ' "$WORK/cx.txt")
[ "$NCX" -eq 5 ] || { echo "FAIL: codex32 split wrote $NCX shares, wanted 5" >&2; exit 1; }
# 127 characters for a 64-byte seed, which is the long codex32 form
CXLEN=$(sed -n 's/^  1  //p' "$WORK/cx.txt" | tr -d '\n' | wc -c)
[ "$CXLEN" -eq 127 ] || { echo "FAIL: a codex32 share is $CXLEN characters, wanted 127" >&2; exit 1; }
grep -q '^  1  ms13kw00' "$WORK/cx.txt" \
    || { echo "FAIL: codex32 share does not carry ms1, the threshold and the id" >&2; exit 1; }
sed -n 's/^  [245]  //p' "$WORK/cx.txt" > "$WORK/cx.pick"
A_CX=$(./kw --regtest backup combine --keystore "$WORK/cx.ks" --passphrase "@$WORK/pass" \
        --shares "@$WORK/cx.pick" 2>/dev/null | awk '/first address/{print $3}')
[ "$A_BK" = "$A_CX" ] || {
    echo "FAIL: three codex32 shares restored $A_CX and not $A_BK" >&2; exit 1; }
# two of five is under the threshold, four is a spare
head -2 "$WORK/cx.pick" > "$WORK/cx.two"
if ./kw --regtest backup combine --keystore "$WORK/cx2.ks" --passphrase "@$WORK/pass" \
        --shares "@$WORK/cx.two" >/dev/null 2>&1; then
    echo "FAIL: two codex32 shares of five combined" >&2; exit 1
fi
sed -n 's/^  [1245]  //p' "$WORK/cx.txt" > "$WORK/cx.four"
if ./kw --regtest backup combine --keystore "$WORK/cx4.ks" --passphrase "@$WORK/pass" \
        --shares "@$WORK/cx.four" >/dev/null 2>&1; then
    echo "FAIL: a spare codex32 share was accepted" >&2; exit 1
fi
# one wrong character must be caught by the checksum, not worked around. The
# replacement is chosen against what is there, since a share whose last
# character already is the one substituted in would come out unaltered.
LASTC=$(sed -n '1s/.*\(.\)$/\1/p' "$WORK/cx.pick")
if [ "$LASTC" = "q" ]; then BADC=p; else BADC=q; fi
sed "1s/.$/$BADC/" "$WORK/cx.pick" > "$WORK/cx.bad"
./kw --regtest backup combine --keystore "$WORK/cx5.ks" --passphrase "@$WORK/pass" \
     --shares "@$WORK/cx.bad" 2>&1 | grep -q "checksum" \
    || { echo "FAIL: a mistyped codex32 share was not caught by its checksum" >&2; exit 1; }
# codex32 has no passphrase, so being given one is an error rather than ignored
if ./kw --regtest backup combine --keystore "$WORK/cx6.ks" --passphrase "@$WORK/pass" \
        --shares "@$WORK/cx.pick" --backup-passphrase "@$WORK/bpass" >/dev/null 2>&1; then
    echo "FAIL: codex32 combine took a backup passphrase" >&2; exit 1
fi
# and the things the format has no room for
for BAD in 1of3 10of12 2of3,3of5; do
    if ./kw --regtest backup split --keystore "$WORK/bk.ks" --passphrase "@$WORK/pass" \
            --format codex32 --groups "$BAD" >/dev/null 2>&1; then
        echo "FAIL: codex32 split accepted --groups $BAD" >&2; exit 1
    fi
done
if ./kw --regtest backup split --keystore "$WORK/bk.ks" --passphrase "@$WORK/pass" \
        --format codex32 --groups 2of3 --id koin >/dev/null 2>&1; then
    echo "FAIL: codex32 split accepted a non-bech32 identifier" >&2; exit 1
fi
if ./kw --regtest backup split --keystore "$WORK/bk.ks" --passphrase "@$WORK/pass" \
        --format bech32 --groups 2of3 >/dev/null 2>&1; then
    echo "FAIL: split accepted an unknown --format" >&2; exit 1
fi

# The psbt crossing: a machine with the account public key composes the spend
# and cannot sign it, and a machine with the keystore signs it and opens no
# socket. No node is needed here because mkutxos builds a set whose amounts are
# bound the same way a scan's are.
PX=$(./kw --regtest export xpub --keystore "$WORK/ks" --passphrase "@$WORK/pass" \
      2>/dev/null | grep -oE '[tx]pub[1-9A-HJ-NP-Za-km-z]+')
[ -n "$PX" ] || { echo "FAIL: no xpub to build from" >&2; exit 1; }
SPKR=$(./kw --regtest address --keystore "$WORK/ks" --passphrase "@$WORK/pass" --index 0 --spk)
./test/mkutxos "$WORK/pb.utxos" "$SPKR" 50000000000 10 \
    || { echo "FAIL: mkutxos for the psbt flow" >&2; exit 1; }

BOUT=$(./kw --regtest psbt build --xpub "$PX" --utxos "$WORK/pb.utxos" \
        --to "$ADDR1:100" --gap 5 2>/dev/null)
PSBT=$(echo "$BOUT" | awk '/^psbt/{print $2}')
[ -n "$PSBT" ] || { echo "FAIL: psbt build printed no psbt" >&2; exit 1; }
echo "$BOUT" | grep -q "^pays    100.00000000 DOGE to $ADDR1" \
    || { echo "FAIL: build did not say what it pays" >&2; echo "$BOUT" >&2; exit 1; }
echo "$BOUT" | grep -q "^change" || { echo "FAIL: build named no change" >&2; exit 1; }

# the build must not have opened the keystore at all
if command -v strace >/dev/null 2>&1; then
    NK=$(strace -f -e trace=openat ./kw --regtest psbt build --xpub "$PX" \
          --utxos "$WORK/pb.utxos" --to "$ADDR1:100" --gap 5 2>&1 >/dev/null \
          | grep -c '^openat.*\.ks' || true)
    [ "$NK" -eq 0 ] || { echo "FAIL: psbt build opened a keystore $NK times" >&2; exit 1; }
fi

printf '%s\n' "$PSBT" > "$WORK/pb.hex"
SOUT=$(./kw --regtest psbt sign --psbt "@$WORK/pb.hex" --keystore "$WORK/ks" \
        --passphrase "@$WORK/pass" --gap 5 2>/dev/null)
echo "$SOUT" | grep -q "^signed  1 of 1" \
    || { echo "FAIL: psbt sign did not sign the input" >&2; echo "$SOUT" >&2; exit 1; }
printf '%s\n' "$(echo "$SOUT" | awk '/^psbt/{print $2}')" > "$WORK/pbs.hex"

# and the signing run must open no socket
if command -v strace >/dev/null 2>&1; then
    NS=$(strace -f -e trace=socket,connect ./kw --regtest psbt sign --psbt "@$WORK/pb.hex" \
          --keystore "$WORK/ks" --passphrase "@$WORK/pass" --gap 5 2>&1 >/dev/null \
          | grep -cE '^(socket|connect)\(' || true)
    [ "$NS" -eq 0 ] || { echo "FAIL: psbt sign opened $NS socket(s)" >&2; exit 1; }
fi

# The signer has to say what it is signing. The builder is the watch-only side,
# which is the side the split assumes may be compromised, and the fee is the one
# number the transaction does not carry: a signer that prints only "signed 1 of
# 1" lets a hostile builder pay a little to the address asked for and the rest
# to the miner. These three are that attack and the two refusals around it.
echo "$SOUT" | grep -q "^out 0 " \
    || { echo "FAIL: psbt sign did not read back its outputs" >&2; echo "$SOUT" >&2; exit 1; }
echo "$SOUT" | grep -qE "^fee +[0-9]+ koinu" \
    || { echo "FAIL: psbt sign did not state the fee" >&2; echo "$SOUT" >&2; exit 1; }
# the change output is named by the path it was derived from, not by position
echo "$SOUT" | grep -q "this wallet, m/44'/1'/0'/1/" \
    || { echo "FAIL: psbt sign did not re-derive the change output" >&2; echo "$SOUT" >&2; exit 1; }

# 100.00000000 DOGE is 10000000000 koinu, little endian 00e40b5402000000, and
# the only output carrying it. Cut it to 1 DOGE and the other 99 go to the
# miner, which is over the cap for a transaction this size.
sed 's/00e40b5402000000/00e1f50500000000/' "$WORK/pb.hex" > "$WORK/pbfee.hex"
cmp -s "$WORK/pb.hex" "$WORK/pbfee.hex" \
    && { echo "FAIL: the fee-attack psbt was not actually modified" >&2; exit 1; }
if ./kw --regtest psbt sign --psbt "@$WORK/pbfee.hex" --keystore "$WORK/ks" \
        --passphrase "@$WORK/pass" --gap 5 >/dev/null 2>&1; then
    echo "FAIL: psbt sign signed a spend paying 99 DOGE to the miner" >&2; exit 1
fi
# and it is the fee that stopped it, not something incidental
./kw --regtest psbt sign --psbt "@$WORK/pbfee.hex" --keystore "$WORK/ks" \
     --passphrase "@$WORK/pass" --gap 5 2>&1 | grep -q "is too high" \
    || { echo "FAIL: psbt sign refused the fee attack for the wrong reason" >&2; exit 1; }

# An input's amount is only as good as the transaction it is read from, so a
# psbt whose attached transaction is not the one the outpoint names understates
# the inputs and so the fee. Flipping one byte of its output script keeps it
# parseable and changes its txid.
sed 's/00743ba40b000000/00743ba40b000001/' "$WORK/pb.hex" > "$WORK/pbutxo.hex"
if cmp -s "$WORK/pb.hex" "$WORK/pbutxo.hex"; then
    echo "FAIL: the prevout amount was not where it was expected" >&2; exit 1
else
    if ./kw --regtest psbt sign --psbt "@$WORK/pbutxo.hex" --keystore "$WORK/ks" \
            --passphrase "@$WORK/pass" --gap 5 >/dev/null 2>&1; then
        echo "FAIL: psbt sign took an input whose transaction is not its outpoint's" >&2
        exit 1
    fi
fi

# extract has to give a transaction, and it has to pay what build said
PRAW=$(./kw --regtest psbt extract --psbt "@$WORK/pbs.hex" 2>/dev/null | awk '{print $NF}')
case "$PRAW" in 01000000*00000000) ;; *) echo "FAIL: extract gave no transaction" >&2; exit 1;; esac
PSHOWN=$(echo "$PRAW" > "$WORK/pbtx.hex"; ./kw --regtest send --tx "@$WORK/pbtx.hex" \
          --node 127.0.0.1 --port 1 2>/dev/null | awk '/^pays/{print $NF; exit}')
[ "$PSHOWN" = "$ADDR1" ] || { echo "FAIL: the psbt paid $PSHOWN, not $ADDR1" >&2; exit 1; }

# the two halves name two different wallets if both are given
if ./kw --regtest psbt build --xpub "$PX" --keystore "$WORK/ks" \
        --utxos "$WORK/pb.utxos" --to "$ADDR1:100" >/dev/null 2>&1; then
    echo "FAIL: psbt build took --xpub and --keystore together" >&2; exit 1
fi
# a string that is not an extended key is not an xpub
if ./kw --regtest psbt build --xpub "notanxpub" --utxos "$WORK/pb.utxos" \
        --to "$ADDR1:100" >/dev/null 2>&1; then
    echo "FAIL: psbt build took a string that is not an extended key" >&2; exit 1
fi
# a psbt whose input this wallet has no key for must not be signed
OTHERSPK=$(./kw --regtest address --keystore "$WORK/bk.ks" --passphrase "@$WORK/pass" --index 0 --spk)
./test/mkutxos "$WORK/pbo.utxos" "$OTHERSPK" 50000000000 10 >/dev/null 2>&1
OPX=$(./kw --regtest export xpub --keystore "$WORK/bk.ks" --passphrase "@$WORK/pass" \
       2>/dev/null | grep -oE '[tx]pub[1-9A-HJ-NP-Za-km-z]+')
OPSBT=$(./kw --regtest psbt build --xpub "$OPX" --utxos "$WORK/pbo.utxos" \
         --to "$ADDR1:100" --gap 5 2>/dev/null | awk '/^psbt/{print $2}')
printf '%s\n' "$OPSBT" > "$WORK/pbo.hex"
if ./kw --regtest psbt sign --psbt "@$WORK/pbo.hex" --keystore "$WORK/ks" \
        --passphrase "@$WORK/pass" --gap 5 >/dev/null 2>&1; then
    echo "FAIL: signed a psbt holding another wallet's input" >&2; exit 1
fi

# A BIP39 passphrase goes into the seed, not the keystore, so the same words
# with and without one are two different wallets. A stolen phrase alone then
# does not spend, and there is nothing to check a wrong passphrase against: it
# restores another valid wallet rather than failing.
printf 'correct horse\n' > "$WORK/seedpass"
MN=$(./kw --regtest new --keystore "$WORK/sp1.ks" --passphrase "@$WORK/pass" --words 12 \
      2>/dev/null | sed -n '2p' | tr -s ' ' | sed 's/^ *//;s/ *$//')
[ -n "$MN" ] || { echo "FAIL: no mnemonic to test the seed passphrase with" >&2; exit 1; }
printf '%s\n' "$MN" > "$WORK/mn"
A_PLAIN=$(./kw --regtest address --keystore "$WORK/sp1.ks" --passphrase "@$WORK/pass")
./kw --regtest restore --keystore "$WORK/sp2.ks" --passphrase "@$WORK/pass" \
     --mnemonic "@$WORK/mn" --seed-passphrase "@$WORK/seedpass" >/dev/null 2>&1 \
    || { echo "FAIL: restore with a seed passphrase failed" >&2; exit 1; }
A_PASS=$(./kw --regtest address --keystore "$WORK/sp2.ks" --passphrase "@$WORK/pass")
[ -n "$A_PLAIN" ] && [ -n "$A_PASS" ] || { echo "FAIL: no addresses to compare" >&2; exit 1; }
[ "$A_PLAIN" != "$A_PASS" ] || {
    echo "FAIL: a seed passphrase produced the same wallet as none" >&2; exit 1; }
# and the same words with the same passphrase reproduce it
./kw --regtest restore --keystore "$WORK/sp3.ks" --passphrase "@$WORK/pass" \
     --mnemonic "@$WORK/mn" --seed-passphrase "@$WORK/seedpass" >/dev/null 2>&1
A_AGAIN=$(./kw --regtest address --keystore "$WORK/sp3.ks" --passphrase "@$WORK/pass")
[ "$A_PASS" = "$A_AGAIN" ] || {
    echo "FAIL: the same words and passphrase gave two wallets" >&2; exit 1; }

# an empty passphrase seals a keystore that opens with nothing
printf '\n' > "$WORK/emptypass"
if ./kw --regtest new --keystore "$WORK/ksempty" --passphrase "@$WORK/emptypass" >/dev/null 2>&1; then
    echo "FAIL: an empty passphrase sealed a keystore" >&2; exit 1
fi

# --input's amount decides the fee, the printed total and the --maxfee cap, and
# legacy sighash does not commit to input value, so a wrong one signs a valid
# transaction that pays the difference to the miner. Where the tracked set knows
# the outpoint, the two have to agree.
SPK0=$(./kw --regtest address --keystore "$WORK/ks" --passphrase "@$WORK/pass" --index 0 --spk)
./test/mkutxos "$WORK/u4" "$SPK0" 100000000000 10 \
    || { echo "FAIL: mkutxos u4" >&2; exit 1; }
# the set stores a txid in internal order and --input takes display order, so
# this reverses the bytes; the old hand-written all-ones txid read the same
# either way and hid the difference. awk rather than tac, which macos does not
# have, the same way test_scan.sh does it.
STORED=$(sed -n 's/^u \([0-9a-f]*\) .*/\1/p' "$WORK/u4")
[ -n "$STORED" ] || { echo "FAIL: no txid in the built set" >&2; exit 1; }
INTXID=$(awk -v s="$STORED" 'BEGIN{o=""; for (i = length(s) - 1; i > 0; i -= 2) o = o substr(s, i, 2); print o}')
if ./kw --regtest sign --keystore "$WORK/ks" --passphrase "@$WORK/pass" --utxos "$WORK/u4" \
       --input "$INTXID:0:10:0" --to "$ADDR1:5" >/dev/null 2>&1; then
    echo "FAIL: signed an --input amount the tracked set disagrees with" >&2; exit 1
fi
./kw --regtest sign --keystore "$WORK/ks" --passphrase "@$WORK/pass" --utxos "$WORK/u4" \
     --input "$INTXID:0:1000:0" --to "$ADDR1:5" >/dev/null \
    || { echo "FAIL: the agreeing amount was refused" >&2; exit 1; }

# What sign reports is read back out of the bytes it signed, not out of the
# request that built them: a signer that prints the request cannot show a
# disagreement between the two. The outputs are printed by index, and the fee is
# the selected inputs less the decoded outputs.
BACK=$(./kw --regtest sign --keystore "$WORK/ks" --passphrase "@$WORK/pass" \
       --utxos "$WORK/u4" --input "$INTXID:0:1000:0" --to "$ADDR1:5" 2>/dev/null)
case "$BACK" in
    *"out 0 pays    5.00000000 DOGE to $ADDR1"*) ;;
    *) echo "FAIL: sign did not read back output 0 from the signed bytes" >&2
       echo "$BACK" >&2; exit 1;;
esac
case "$BACK" in
    *"out 1 change"*) ;;
    *) echo "FAIL: sign did not read back the change output" >&2; exit 1;;
esac
# the fee is inputs less decoded outputs, so it is whatever is left of the 10
case "$BACK" in
    *"fee   "*) ;;
    *) echo "FAIL: sign printed no fee" >&2; exit 1;;
esac


# cosign: two fixed keys (0x11.., 0x22..) co-sign a 2-of-2 P2SH spend. The
# unsigned tx and redeem script match test_tx's fixtures; outputs are
# deterministic (RFC 6979) so they are pinned.
printf 'cN9spWsvaxA8taS7DFMxnk1yJD2gaF2PX1npuTpy3vuZFJdwavaw\n' > "$WORK/w1"
printf 'cNj3zTdrLAMQtUhdFPPVJtRY7a3TdUF38ShW5MrJkVh1CVaeuEGU\n' > "$WORK/w2"
REDEEM=5221034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa2102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f2752ae
# the coin being spent, since cosign binds --redeem to it
PREV=010000000111000000000000000000000000000000000000000000000000000000000000110000000000ffffffff0100c2eb0b0000000017a91463859964ea29ad5a0916500860e2c4adec0a6b278700000000
UNSIGNED=010000000110a4f36cb349552094f0127a50b0d2bf8c6c02eab28b394957a5631c2a6989350000000000ffffffff0100e1f505000000001976a914111111111111111111111111111111111111111188ac00000000
SIGA=$(./kw --regtest cosign --tx "$UNSIGNED" --redeem "$REDEEM" --utxo "$PREV" --wif "@$WORK/w1")
WANTSIG=3045022100d812e692e83b7500f63ad59e77ba311532bf036104e1ccf3f914708add70aba10220281c316713e6ec4afaf6d01f91e22dbaea638263df3213ce49fbd83a73ca102701
[ "$SIGA" = "$WANTSIG" ] || { echo "FAIL: cosign signature mismatch" >&2; exit 1; }
FULL=$(./kw --regtest cosign --tx "$UNSIGNED" --redeem "$REDEEM" --utxo "$PREV" --wif "@$WORK/w2" --sig "$SIGA" --finish)
case "$FULL" in *"$SIGA"*"$REDEEM"*) ;; *) echo "FAIL: finished tx missing sig or redeem" >&2; exit 1;; esac
FULL2=$(./kw --regtest cosign --tx "$UNSIGNED" --redeem "$REDEEM" --utxo "$PREV" --wif "@$WORK/w2" --sig "$SIGA" --finish)
[ "$FULL" = "$FULL2" ] || { echo "FAIL: cosign not deterministic" >&2; exit 1; }

# bytes after the transaction are not part of it, so the txid send would report
# is not the transaction's
if ./kw --regtest send --tx "${FULL}deadbeef" --node 127.0.0.1 --yes >/dev/null 2>&1; then
    echo "FAIL: broadcast a transaction with trailing bytes" >&2; exit 1
fi

# cosign refuses a script that does not name the signing key. --redeem set to the
# p2pkh scriptPubKey of a coin that key holds would otherwise make the
# "cosignature" a valid p2pkh spend of it to wherever --tx pays.
P2PKH=76a914$(printf '%040d' 0)88ac
if ./kw --regtest cosign --tx "$UNSIGNED" --redeem "$P2PKH" --utxo "$PREV" --wif "@$WORK/w1" >/dev/null 2>&1; then
    echo "FAIL: cosign signed a script that does not name its key" >&2; exit 1
fi
# a script that names one key spends with that key alone, however it is dressed
# up, so signing it is a spend of that coin rather than a co-signature. core's
# generate pays p2pk, so the key for one is exactly the external wif this takes.
# Refusing the exact 35-byte p2pk shape caught none of the rest: the 1-of-1 and
# the OP_IF both reached a node's mempool as 1-of-1 spends.
PUB1=034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa
for ONE in "21${PUB1}ac" "5121${PUB1}51ae" "21${PUB1}ac61" "21${PUB1}ad51" \
           "6321${PUB1}ac6721${PUB1}ac68"; do
    if ./kw --regtest cosign --tx "$UNSIGNED" --redeem "$ONE" --utxo "$PREV" \
           --wif "@$WORK/w1" >/dev/null 2>&1; then
        echo "FAIL: cosign signed a script naming one key: $ONE" >&2; exit 1
    fi
done
# and nothing ties the script to the coin without --utxo, so it is required
if ./kw --regtest cosign --tx "$UNSIGNED" --redeem "$REDEEM" --wif "@$WORK/w1" >/dev/null 2>&1; then
    echo "FAIL: cosign signed without --utxo" >&2; exit 1
fi

# and the summary goes to stderr, so stdout is still one signature
LINES=$(./kw --regtest cosign --tx "$UNSIGNED" --redeem "$REDEEM" --utxo "$PREV" --wif "@$WORK/w1" 2>/dev/null | wc -l)
[ "$LINES" -eq 1 ] || { echo "FAIL: cosign printed $LINES lines on stdout, want 1" >&2; exit 1; }

# a wrong hashtype and a duplicated key must be refused
if ./kw --regtest cosign --tx "$UNSIGNED" --redeem "$REDEEM" --utxo "$PREV" --wif "@$WORK/w2" \
       --sig "${SIGA%01}00" --finish >/dev/null 2>&1; then
    echo "FAIL: cosign accepted a non-SIGHASH_ALL signature" >&2; exit 1
fi
if ./kw --regtest cosign --tx "$UNSIGNED" --redeem "$REDEEM" --utxo "$PREV" --wif "@$WORK/w1" \
       --sig "$SIGA" --finish >/dev/null 2>&1; then
    echo "FAIL: cosign accepted the same key twice" >&2; exit 1
fi

# psbt: the bip174 roles over the cli, two parties signing separately. The
# extracted transaction must equal what cosign --finish builds from the same
# keys, since both assemble the same 2-of-2 scriptSig.
# A signer checks the redeem script against the coin it spends, so the psbt
# carries the previous transaction. PREVTX pays 1 DOGE to p2sh(REDEEM) and
# UNSIGNEDP spends its output 0, which is why this is not the cosign fixture
# above: that one's prevout is invented and no transaction hashes to it.
PREVTX=01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff0100e1f5050000000017a91463859964ea29ad5a0916500860e2c4adec0a6b278700000000
UNSIGNEDP=01000000019d497df886db6fdaa7dcb2fd81171034944b9f5a0a0446a54ec2ddad4b21223f0000000000ffffffff01c09ee605000000001976a914111111111111111111111111111111111111111188ac00000000
P0=$(./kw --regtest psbt create --tx "$UNSIGNEDP" --utxo "$PREVTX" --vin 0)
case "$P0" in 70736274ff*) ;; *) echo "FAIL: psbt create magic" >&2; exit 1;; esac
[ "$(./kw --regtest psbt tx --psbt "$P0")" = "$UNSIGNEDP" ] || { echo "FAIL: psbt tx accessor" >&2; exit 1; }
# without the utxo there is nothing to check the redeem script against
P0BARE=$(./kw --regtest psbt create --tx "$UNSIGNEDP")
if ./kw --regtest psbt sign --psbt "$P0BARE" --wif "@$WORK/w1" --redeem "$REDEEM" --vin 0 >/dev/null 2>&1; then
    echo "FAIL: signed a psbt with no utxo to check against" >&2; exit 1
fi
# and a redeem script that is not what the utxo pays is refused
if ./kw --regtest psbt sign --psbt "$P0" --wif "@$WORK/w1" --vin 0 \
       --redeem 76a914111111111111111111111111111111111111111188ac >/dev/null 2>&1; then
    echo "FAIL: signed a script the utxo does not pay" >&2; exit 1
fi
PA=$(./kw --regtest psbt sign --psbt "$P0" --wif "@$WORK/w1" --redeem "$REDEEM" --vin 0)
PB=$(./kw --regtest psbt sign --psbt "$P0" --wif "@$WORK/w2" --redeem "$REDEEM" --vin 0)
[ "$PA" != "$PB" ] || { echo "FAIL: both keys produced the same psbt" >&2; exit 1; }
PC=$(./kw --regtest psbt combine --psbt "$PA" --psbt "$PB")
# -eq not =, since BSD wc pads its count with leading spaces
NSIG=$(./kw --regtest psbt sigs --psbt "$PC" | wc -l)
[ "$NSIG" -eq 2 ] || { echo "FAIL: combine kept $NSIG signatures" >&2; exit 1; }
# combining is idempotent, so a replayed half cannot inflate the set
NSIG2=$(./kw --regtest psbt combine --psbt "$PC" --psbt "$PA" | ./kw --regtest psbt sigs --psbt - | wc -l)
[ "$NSIG2" -eq 2 ] || { echo "FAIL: combine not idempotent" >&2; exit 1; }
SS=$(./kw --regtest psbt sigs --psbt "$PC" | awk '{printf "%02x%s", length($3)/2, $3}')
SS="00${SS}$(printf '%02x' $((${#REDEEM}/2)))$REDEEM"
PF=$(./kw --regtest psbt finalize --psbt "$PC" --vin 0 --scriptsig "$SS")
EXTRACTED=$(./kw --regtest psbt extract --psbt "$PF")
SIGAP=$(./kw --regtest cosign --tx "$UNSIGNEDP" --redeem "$REDEEM" --utxo "$PREVTX" --wif "@$WORK/w1")
FULLP=$(./kw --regtest cosign --tx "$UNSIGNEDP" --redeem "$REDEEM" --utxo "$PREVTX" --wif "@$WORK/w2" --sig "$SIGAP" --finish)
[ "$EXTRACTED" = "$FULLP" ] || { echo "FAIL: psbt and cosign disagree on the transaction" >&2; exit 1; }
# extracting before every input is final must fail
if ./kw --regtest psbt extract --psbt "$PC" >/dev/null 2>&1; then
    echo "FAIL: extracted an unfinalized psbt" >&2; exit 1
fi

echo "cli ok: new/address round trip, index varies, wrong passphrase and clobber refused, sign deterministic, change rotates between spends and past spent addresses, too many inputs refused, --input amounts checked against the set, amounts bounded, one spelling per outpoint, no empty passphrase, broadcast needs --yes, journaled once per spend, send decodes and confirms, cosign 2-of-2 bound to its key, psbt roles agree with cosign, a seed passphrase makes another wallet from the same words, backup verify checks a phrase without revealing it, a threshold of shares restores the wallet and fewer restore nothing, codex32 the same in base32, a psbt built from an xpub and signed without a socket, sign --raw pipes into send"
