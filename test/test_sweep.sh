#!/usr/bin/env bash
# kw sweep against a regtest node: the fee bound on the path that spends an
# entire key. Skips when dogecoind is absent or its regtest port is taken, so
# make check stays hermetic.
set -eu
cd "$(dirname "$0")/.."

command -v dogecoind >/dev/null 2>&1 || { echo "sweep skipped: no dogecoind"; exit 0; }
command -v dogecoin-cli >/dev/null 2>&1 || { echo "sweep skipped: no dogecoin-cli"; exit 0; }
if (exec 3<>/dev/tcp/127.0.0.1/18444) 2>/dev/null; then
    exec 3>&- 2>/dev/null || true
    echo "sweep skipped: port 18444 in use"; exit 0
fi

D=$(mktemp -d)
cleanup() { dogecoin-cli -regtest -datadir="$D" stop >/dev/null 2>&1 || true; sleep 1; rm -rf "$D"; }
trap cleanup EXIT

dogecoind -regtest -datadir="$D" -daemon >/dev/null 2>&1 || { echo "sweep skipped: dogecoind would not start"; exit 0; }
C="dogecoin-cli -regtest -datadir=$D"
for _ in $(seq 1 20); do $C getblockcount >/dev/null 2>&1 && break; sleep 1; done
$C getblockcount >/dev/null 2>&1 || { echo "sweep skipped: regtest node never came up"; exit 0; }

MINE=$($C getnewaddress)
$C generatetoaddress 101 "$MINE" >/dev/null
ADDR=$($C getnewaddress)
$C dumpprivkey "$ADDR" > "$D/wif"
$C sendtoaddress "$ADDR" 501 >/dev/null
$C generatetoaddress 3 "$MINE" >/dev/null
DEST=$($C getnewaddress)

# step one is the networked half and reads no key: an address, a node, a file
./kw --regtest sweep --watch "$ADDR" --utxos "$D/u" --node 127.0.0.1 --port 18444 --spv \
     >/dev/null 2>&1 || { echo "FAIL: the --watch step failed" >&2; exit 1; }
[ -f "$D/u" ] || { echo "FAIL: the --watch step wrote no utxo set" >&2; exit 1; }
[ -f "$D/u.meta" ] || { echo "FAIL: the --watch step wrote no metadata" >&2; exit 1; }

# step two signs from that file and opens no socket, so no --node is given
SWEEP="./kw --regtest sweep --wif @$D/wif --to $DEST --utxos $D/u"

# the halves must not be combinable, which is the whole point of the split
if ./kw --regtest sweep --watch "$ADDR" --wif "@$D/wif" --to "$DEST" --utxos "$D/u" \
        --node 127.0.0.1 --port 18444 >/dev/null 2>&1; then
    echo "FAIL: --watch and --wif were accepted in one run" >&2; exit 1
fi
# and a sign step with no file to read must say so rather than reach for a peer
if ./kw --regtest sweep --wif "@$D/wif" --to "$DEST" --utxos "$D/nosuch" \
        >/dev/null 2>&1; then
    echo "FAIL: signing with no utxo set succeeded" >&2; exit 1
fi

# a set of someone else's coins is left out rather than signed into a
# transaction the network refuses
OTHER=$($C getnewaddress)
./kw --regtest sweep --watch "$OTHER" --utxos "$D/other" --node 127.0.0.1 --port 18444 --spv \
     >/dev/null 2>&1 || { echo "FAIL: the --watch step for another address failed" >&2; exit 1; }
$C sendtoaddress "$OTHER" 7 >/dev/null
$C generatetoaddress 3 "$MINE" >/dev/null
./kw --regtest sweep --watch "$OTHER" --utxos "$D/other" --node 127.0.0.1 --port 18444 --spv \
     >/dev/null 2>&1
if ./kw --regtest sweep --wif "@$D/wif" --to "$DEST" --utxos "$D/other" >/dev/null 2>&1; then
    echo "FAIL: swept a utxo set holding no coins of this key" >&2; exit 1
fi

# 500 DOGE on a ~191 byte transaction is six orders of magnitude over the rate.
# Before the bound this signed, sending 1 DOGE and paying the other 500.
if $SWEEP --fee 500 >/dev/null 2>&1; then
    echo "FAIL: swept a 501 DOGE key paying a 500 DOGE fee" >&2; exit 1
fi

# the same fee is allowed when named explicitly, since that is a decision
$SWEEP --fee 500 --maxfee 500 >/dev/null 2>&1 \
    || { echo "FAIL: --maxfee 500 did not permit a 500 DOGE fee" >&2; exit 1; }

# and the default rate costs a fraction of a DOGE: under 0.01 for one input
OUT=$($SWEEP 2>/dev/null)
FEE=$(echo "$OUT" | awk '/^fee/{print $2}')
[ -n "$FEE" ] || { echo "FAIL: default sweep produced no fee line" >&2; exit 1; }
[ "$FEE" -gt 0 ] || { echo "FAIL: default sweep paid no fee" >&2; exit 1; }
[ "$FEE" -lt 1000000 ] || { echo "FAIL: default sweep fee $FEE koinu is over 0.01 DOGE" >&2; exit 1; }

# the swept output must be the balance less that fee, so nothing is left behind
SWEPT=$(echo "$OUT" | awk '/^swept/{print $4}')
[ "$((SWEPT + FEE))" -eq 50100000000 ] || \
    { echo "FAIL: swept $SWEPT + fee $FEE does not account for 501 DOGE" >&2; exit 1; }

echo "sweep ok: two steps, the halves refused in one run, another key's set refused,"
echo "  500 DOGE fee refused, --maxfee permits it, default fee $FEE koinu accounts for the balance"
