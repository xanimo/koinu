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

# sign: spend a fixed outpoint to our own address, deterministic and well-formed
IN="0000000000000000000000000000000000000000000000000000000000000001:0:10.0:0"
RAW1=$(./kw --regtest sign --keystore "$WORK/ks" --passphrase "@$WORK/pass" \
       --input "$IN" --to "$ADDR1:8.5" --fee 0.001 | awk '/^raw/{print $2}')
[ -n "$RAW1" ] || { echo "FAIL: sign produced no raw tx" >&2; exit 1; }
case "$RAW1" in 01000000*00000000) ;; *) echo "FAIL: raw tx not well-formed" >&2; exit 1;; esac
RAW2=$(./kw --regtest sign --keystore "$WORK/ks" --passphrase "@$WORK/pass" \
       --input "$IN" --to "$ADDR1:8.5" --fee 0.001 | awk '/^raw/{print $2}')
[ "$RAW1" = "$RAW2" ] || { echo "FAIL: sign not deterministic" >&2; exit 1; }
# a different amount must change the transaction
RAW3=$(./kw --regtest sign --keystore "$WORK/ks" --passphrase "@$WORK/pass" \
       --input "$IN" --to "$ADDR1:8.0" --fee 0.001 | awk '/^raw/{print $2}')
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
{ echo "# koinu utxo set v1"
  echo "0000000000000000000000000000000000000000000000000000000000000002 0 1000000000 1 $SPK0"
} > "$WORK/ks.utxos"
CH=$(./kw --regtest sign --keystore "$WORK/ks" --passphrase "@$WORK/pass" \
     --input "$IN" --to "$ADDR1:8.5" --fee 0.001 | awk '/^change/{print $2}')
[ "$CH" = "m/44'/1'/0'/1/1" ] || { echo "FAIL: change went to $CH, want index 1" >&2; exit 1; }
rm -f "$WORK/ks.utxos"

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

# cosign: two fixed keys (0x11.., 0x22..) co-sign a 2-of-2 P2SH spend. The
# unsigned tx and redeem script match test_tx's fixtures; outputs are
# deterministic (RFC 6979) so they are pinned.
printf 'cN9spWsvaxA8taS7DFMxnk1yJD2gaF2PX1npuTpy3vuZFJdwavaw\n' > "$WORK/w1"
printf 'cNj3zTdrLAMQtUhdFPPVJtRY7a3TdUF38ShW5MrJkVh1CVaeuEGU\n' > "$WORK/w2"
REDEEM=5221034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa2102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f2752ae
UNSIGNED=0100000001ffeeddccbbaa99887766554433221100ffeeddccbbaa998877665544332211000000000000ffffffff0100e1f505000000001976a914111111111111111111111111111111111111111188ac00000000
SIGA=$(./kw --regtest cosign --tx "$UNSIGNED" --redeem "$REDEEM" --wif "@$WORK/w1")
WANTSIG=304402207fce6e4d513888e576c636c4990e1ce638f745504eae9f5633b4f3977a71102902201f4b3f8a7fcf1c55c17ecec5b9c27e25cfab3e7c8c0ce497a046995209f766c401
[ "$SIGA" = "$WANTSIG" ] || { echo "FAIL: cosign signature mismatch" >&2; exit 1; }
FULL=$(./kw --regtest cosign --tx "$UNSIGNED" --redeem "$REDEEM" --wif "@$WORK/w2" --sig "$SIGA" --finish)
case "$FULL" in *"$SIGA"*"$REDEEM"*) ;; *) echo "FAIL: finished tx missing sig or redeem" >&2; exit 1;; esac
FULL2=$(./kw --regtest cosign --tx "$UNSIGNED" --redeem "$REDEEM" --wif "@$WORK/w2" --sig "$SIGA" --finish)
[ "$FULL" = "$FULL2" ] || { echo "FAIL: cosign not deterministic" >&2; exit 1; }
# a wrong hashtype and a duplicated key must be refused
if ./kw --regtest cosign --tx "$UNSIGNED" --redeem "$REDEEM" --wif "@$WORK/w2" \
       --sig "${SIGA%01}00" --finish >/dev/null 2>&1; then
    echo "FAIL: cosign accepted a non-SIGHASH_ALL signature" >&2; exit 1
fi
if ./kw --regtest cosign --tx "$UNSIGNED" --redeem "$REDEEM" --wif "@$WORK/w1" \
       --sig "$SIGA" --finish >/dev/null 2>&1; then
    echo "FAIL: cosign accepted the same key twice" >&2; exit 1
fi

# psbt: the bip174 roles over the cli, two parties signing separately. The
# extracted transaction must equal what cosign --finish builds from the same
# keys, since both assemble the same 2-of-2 scriptSig.
P0=$(./kw --regtest psbt create --tx "$UNSIGNED")
case "$P0" in 70736274ff*) ;; *) echo "FAIL: psbt create magic" >&2; exit 1;; esac
[ "$(./kw --regtest psbt tx --psbt "$P0")" = "$UNSIGNED" ] || { echo "FAIL: psbt tx accessor" >&2; exit 1; }
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
[ "$EXTRACTED" = "$FULL" ] || { echo "FAIL: psbt and cosign disagree on the transaction" >&2; exit 1; }
# extracting before every input is final must fail
if ./kw --regtest psbt extract --psbt "$PC" >/dev/null 2>&1; then
    echo "FAIL: extracted an unfinalized psbt" >&2; exit 1
fi

echo "cli ok: new/address round trip, index varies, wrong passphrase and clobber refused, sign deterministic, change rotates, too many inputs refused, journaled once per spend, send decodes and confirms, cosign 2-of-2, psbt roles agree with cosign"
