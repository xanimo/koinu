#!/usr/bin/env bash
# kw sweep against a regtest node: the fee bound on the path that spends an
# entire key. Skips when dogecoind is absent, so make check stays hermetic.
#
# Its ports are found rather than assumed. On the default pair this suite
# skipped whenever any other regtest node was up on the machine, and the run
# still exited 0 and printed no failure, so a release went out with the sweep
# path untested and nothing said so.
set -eu
cd "$(dirname "$0")/.."

command -v dogecoind >/dev/null 2>&1 || { echo "sweep skipped: no dogecoind"; exit 0; }
command -v dogecoin-cli >/dev/null 2>&1 || { echo "sweep skipped: no dogecoin-cli"; exit 0; }

port_free() { ! (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null; }
P2P=""
for p in $(seq 18444 2 18542); do
    if port_free "$p" && port_free "$((p + 1))"; then P2P=$p; break; fi
done
[ -n "$P2P" ] || { echo "FAIL: no free port pair in 18444-18542" >&2; exit 1; }
RPC=$((P2P + 1))

D=$(mktemp -d)
C="dogecoin-cli -regtest -datadir=$D -rpcport=$RPC"
cleanup() { $C stop >/dev/null 2>&1 || true; sleep 1; rm -rf "$D"; }
trap cleanup EXIT

# Failures from here on, not skips: dogecoind is installed and the ports are
# free, so a node that will not come up is this suite's problem to report.
dogecoind -regtest -datadir="$D" -port=$P2P -rpcport=$RPC -daemon >/dev/null 2>&1 \
    || { echo "FAIL: dogecoind would not start on $P2P" >&2; exit 1; }
for _ in $(seq 1 20); do $C getblockcount >/dev/null 2>&1 && break; sleep 1; done
$C getblockcount >/dev/null 2>&1 || { echo "FAIL: the regtest node never came up" >&2; exit 1; }

MINE=$($C getnewaddress)
$C generatetoaddress 101 "$MINE" >/dev/null
ADDR=$($C getnewaddress)
$C dumpprivkey "$ADDR" > "$D/wif"
$C sendtoaddress "$ADDR" 501 >/dev/null
$C generatetoaddress 3 "$MINE" >/dev/null
DEST=$($C getnewaddress)

# step one is the networked half and reads no key: an address, a node, a file
./kw --regtest sweep --watch "$ADDR" --utxos "$D/u" --node 127.0.0.1 --port $P2P --spv \
     >/dev/null 2>&1 || { echo "FAIL: the --watch step failed" >&2; exit 1; }
[ -f "$D/u" ] || { echo "FAIL: the --watch step wrote no utxo set" >&2; exit 1; }
[ -f "$D/u.meta" ] || { echo "FAIL: the --watch step wrote no metadata" >&2; exit 1; }

# step two signs from that file and opens no socket, so no --node is given
SWEEP="./kw --regtest sweep --wif @$D/wif --to $DEST --utxos $D/u"

# the halves must not be combinable, which is the whole point of the split
if ./kw --regtest sweep --watch "$ADDR" --wif "@$D/wif" --to "$DEST" --utxos "$D/u" \
        --node 127.0.0.1 --port $P2P >/dev/null 2>&1; then
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
./kw --regtest sweep --watch "$OTHER" --utxos "$D/other" --node 127.0.0.1 --port $P2P --spv \
     >/dev/null 2>&1 || { echo "FAIL: the --watch step for another address failed" >&2; exit 1; }
$C sendtoaddress "$OTHER" 7 >/dev/null
$C generatetoaddress 3 "$MINE" >/dev/null
./kw --regtest sweep --watch "$OTHER" --utxos "$D/other" --node 127.0.0.1 --port $P2P --spv \
     >/dev/null 2>&1
if ./kw --regtest sweep --wif "@$D/wif" --to "$DEST" --utxos "$D/other" >/dev/null 2>&1; then
    echo "FAIL: swept a utxo set holding no coins of this key" >&2; exit 1
fi

# A sweep sends the whole balance, so --to takes an address and no amount. It
# split on a colon and dropped whatever followed, so somebody carrying kw sign's
# ADDR:AMOUNT spelling over swept everything: --to DEST:5 moved 999.99 DOGE of a
# 1000 DOGE key and reported success. Refused now, and the refusal says which
# command does take an amount.
if ./kw --regtest sweep --wif "@$D/wif" --to "$DEST:5" --utxos "$D/u" >/dev/null 2>&1; then
    echo "FAIL: --to DEST:5 swept the balance instead of being refused" >&2; exit 1
fi
./kw --regtest sweep --wif "@$D/wif" --to "$DEST:5" --utxos "$D/u" 2>&1     | grep -q "sends the whole"     || { echo "FAIL: --to DEST:5 was refused for some other reason" >&2; exit 1; }
# and a bare address still works, so the check is not refusing everything
$SWEEP >/dev/null 2>&1 || { echo "FAIL: a bare --to address no longer sweeps" >&2; exit 1; }

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
