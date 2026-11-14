#!/usr/bin/env bash
# kwd's filter line has to follow the chain, not the moment it started.
#
# settle_filters ran once from main and g_cfsettled never moved, so every block
# mined while kwd was up sat above the line and was fetched whole on every
# outpoint query that reached it: a hundred blocks after startup a query fetched
# a hundred, five hundred after it fetched five hundred, and restarting put the
# line back at the tip. A caller that gives the backend a few seconds stops
# getting an answer at all, and payment-channel's confirm budget is three.
#
# Needs a node that serves compact filters. Skips when dogecoind is absent, so
# make check stays hermetic. Its ports are found rather than assumed, for the
# reason test_scan.sh says.
set -eu
cd "$(dirname "$0")/.."

command -v dogecoind >/dev/null 2>&1 || { echo "kwdsettle skipped: no dogecoind"; exit 0; }
command -v dogecoin-cli >/dev/null 2>&1 || { echo "kwdsettle skipped: no dogecoin-cli"; exit 0; }
dogecoind -help 2>/dev/null | grep -q blockfilterindex \
    || { echo "kwdsettle skipped: this dogecoind serves no compact filters"; exit 0; }

port_free() { ! (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null; }
P2P=""
for p in $(seq 18644 2 18742); do
    if port_free "$p" && port_free "$((p + 1))"; then P2P=$p; break; fi
done
[ -n "$P2P" ] || { echo "FAIL: no free port pair in 18644-18742" >&2; exit 1; }
RPC=$((P2P + 1))

D=$(mktemp -d)
C="dogecoin-cli -regtest -rpcport=$RPC -datadir=$D"
cleanup() { pkill -x kwd 2>/dev/null || true; $C stop >/dev/null 2>&1 || true; sleep 1; rm -rf "$D"; }
trap cleanup EXIT INT TERM

dogecoind -regtest -datadir="$D" -port=$P2P -rpcport=$RPC \
    -blockfilterindex=1 -peerblockfilters=1 -daemon >/dev/null 2>&1 \
    || { echo "FAIL: dogecoind would not start on $P2P" >&2; exit 1; }
for _ in $(seq 1 25); do $C getblockcount >/dev/null 2>&1 && break; sleep 1; done
$C getblockcount >/dev/null 2>&1 || { echo "FAIL: the regtest node never came up" >&2; exit 1; }

MINE=$($C getnewaddress)
$C generatetoaddress 150 "$MINE" >/dev/null
ADDR=$($C getnewaddress)
TX=$($C sendtoaddress "$ADDR" 10)
$C generatetoaddress 6 "$MINE" >/dev/null
VOUT=$($C gettransaction "$TX" | tr ',' '\n' | grep -A2 '"receive"' | grep '"vout"' | tr -dc '0-9')
[ -n "$VOUT" ] || VOUT=0

./kwd --regtest --node "127.0.0.1:$P2P" --socket "$D/kwd.sock" \
      --headers "$D/h.kwh" --filters "$D/f.cf" > "$D/kwd.log" 2>&1 &
for _ in $(seq 1 40); do grep -q "ready" "$D/kwd.log" 2>/dev/null && break; sleep 1; done
grep -q "ready" "$D/kwd.log" || { echo "FAIL: kwd never became ready" >&2
                                  sed 's/^/    /' "$D/kwd.log" >&2; exit 1; }
START=$($C getblockcount)

ask() {
    ./kw --regtest outpoint --watch "$ADDR" --outpoint "$TX:$VOUT" \
         --since 150 --daemon "$D/kwd.sock" 2>&1 | head -1
}
# "ready" is printed before the first filter sync has necessarily finished, so
# the very first question can race it. Retried rather than slept on, since the
# thing being measured afterwards is a count and not a time.
FIRST=""
for _ in $(seq 1 15); do
    FIRST=$(ask)
    echo "$FIRST" | grep -q "unspent" && break
    sleep 1
done
echo "$FIRST" | grep -q "unspent" \
    || { echo "FAIL: the outpoint was not found at startup: $FIRST" >&2
         sed 's/^/    kwd: /' "$D/kwd.log" >&2; exit 1; }

# Anything the startup race caused does not count against what follows.
: > "$D/kwd.log.mark"
WHOLE0=$(grep -c "fetched whole" "$D/kwd.log" || true)

# Grow the chain well past where kwd started, then ask again.
$C generatetoaddress 200 "$MINE" >/dev/null
sleep 3
OUT=$(ask)
echo "$OUT" | grep -q "unspent" \
    || { echo "FAIL: the outpoint was lost after 200 blocks: $OUT" >&2; exit 1; }

# The finding: those 200 blocks were above a line fixed at startup, so every one
# of them was downloaded whole to answer a question the filters could answer.
WHOLE=$(( $(grep -c "fetched whole" "$D/kwd.log" || true) - WHOLE0 ))
[ "$WHOLE" -le 0 ] || {
    echo "FAIL: kwd fetched blocks whole above a line it set at startup" >&2
    grep "fetched whole" "$D/kwd.log" | sed 's/^/    /' >&2
    exit 1
}

# And a second round, so this is not just the first query happening to be cheap.
$C generatetoaddress 200 "$MINE" >/dev/null
sleep 3
ask | grep -q "unspent" || { echo "FAIL: the outpoint was lost after 400 blocks" >&2; exit 1; }
WHOLE=$(( $(grep -c "fetched whole" "$D/kwd.log" || true) - WHOLE0 ))
[ "$WHOLE" -le 0 ] || {
    echo "FAIL: kwd fetched blocks whole on the second round" >&2
    grep "fetched whole" "$D/kwd.log" | sed 's/^/    /' >&2
    exit 1
}

NOW=$($C getblockcount)
echo "kwdsettle ok: kwd started at $START, the chain reached $NOW, and no block"
echo "  above the startup line was fetched whole"
