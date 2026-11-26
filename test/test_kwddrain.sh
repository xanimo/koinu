#!/usr/bin/env bash
# One drain must be bounded by time as well as by message count.
#
# drain_peer stopped after KWD_DRAIN_MAX messages, and kw_peer_recv returns only
# once a whole message is in, so a peer that sent half a ping and stopped held
# the accept loop for the socket timeout and one dribbling a byte held it for the
# exchange timeout: measured at 12.3s and 117.1s here, both of them blocking a
# cfheaders request that needed no peer at all. payment-channel's confirm budget
# is three seconds.
#
# Only the bound is measured here. That a drain still answers a real node's ping
# across a long idle, which is the half this bound could have broken, is what
# test_kwdsettle.sh checks when it watches bytesrecv move after 150 seconds.
#
# Needs a node that serves compact filters. Skips when dogecoind is absent, so
# make check stays hermetic. Its ports are found rather than assumed, for the
# reason test_scan.sh says.
set -eu
cd "$(dirname "$0")/.."

command -v dogecoind >/dev/null 2>&1 || { echo "kwddrain skipped: no dogecoind"; exit 0; }
command -v dogecoin-cli >/dev/null 2>&1 || { echo "kwddrain skipped: no dogecoin-cli"; exit 0; }
dogecoind -help 2>/dev/null | grep -q blockfilterindex \
    || { echo "kwddrain skipped: this dogecoind serves no compact filters"; exit 0; }
[ -x ./test/stallrelay ] || { echo "FAIL: test/stallrelay was not built" >&2; exit 1; }

port_free() { ! (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null; }
P2P=""
for p in $(seq 18844 3 18941); do
    if port_free "$p" && port_free "$((p + 1))" && port_free "$((p + 2))"; then P2P=$p; break; fi
done
[ -n "$P2P" ] || { echo "FAIL: no free port triple in 18844-18941" >&2; exit 1; }
RPC=$((P2P + 1))
RELAY=$((P2P + 2))

D=$(mktemp -d)
C="dogecoin-cli -regtest -rpcport=$RPC -datadir=$D"
RELAY_PID=""
cleanup() {
    pkill -x kwd 2>/dev/null || true
    [ -n "$RELAY_PID" ] && kill "$RELAY_PID" 2>/dev/null
    $C stop >/dev/null 2>&1 || true
    sleep 1
    rm -rf "$D"
}
trap cleanup EXIT INT TERM

dogecoind -regtest -datadir="$D" -port=$P2P -rpcport=$RPC \
    -blockfilterindex=1 -peerblockfilters=1 -daemon >/dev/null 2>&1 \
    || { echo "FAIL: dogecoind would not start on $P2P" >&2; exit 1; }
for _ in $(seq 1 25); do $C getblockcount >/dev/null 2>&1 && break; sleep 1; done
$C getblockcount >/dev/null 2>&1 || { echo "FAIL: the regtest node never came up" >&2; exit 1; }
$C generatetoaddress 120 "$($C getnewaddress)" >/dev/null

# How long a request that is served entirely from the local cache takes, in
# milliseconds. cfheaders 1 1 reads one header kwd already has.
ask() {
    local a b
    a=$(date +%s%N)
    printf 'cfheaders 1 1\n' | timeout 300 nc -U "$D/sock" >/dev/null 2>&1 || true
    b=$(date +%s%N)
    echo $(( (b - a) / 1000000 ))
}

# A drain runs between requests, so the stall has to be in place before the
# second one. Both modes get their own kwd: once the peer is dropped the next
# connection through the relay passes untouched and there is nothing left to
# measure.
run() {
    local mode=$1 warm stalled
    pkill -x kwd 2>/dev/null || true
    sleep 1
    rm -f "$D/sock" "$D/trigger" "$D/kwh" "$D/cf"*
    ./test/stallrelay $RELAY $P2P "$D/trigger" "$mode" >/dev/null 2>&1 &
    RELAY_PID=$!
    sleep 1
    ./kwd --regtest --node 127.0.0.1:$RELAY --socket "$D/sock" \
          --headers "$D/kwh" --filters "$D/cf" >"$D/kwd.log" 2>&1 &
    for _ in $(seq 1 40); do grep -q ready "$D/kwd.log" 2>/dev/null && break; sleep 1; done
    grep -q ready "$D/kwd.log" 2>/dev/null || { echo "FAIL: kwd never became ready ($mode)" >&2; exit 1; }

    warm=$(ask)
    [ "$warm" -lt 2000 ] || { echo "FAIL: a cached request took ${warm}ms with no stall at all ($mode)" >&2; exit 1; }
    touch "$D/trigger"
    sleep 2
    stalled=$(ask)
    pkill -x kwd 2>/dev/null || true
    kill "$RELAY_PID" 2>/dev/null
    RELAY_PID=""
    echo "$warm $stalled"
}

# 3s is payment-channel's budget and KWD_DRAIN_MS is 1s, so this passes with
# room and still fails by an order of magnitude against the old drain: 12343ms
# for once and 117062ms for dribble.
check() {
    local mode=$1 r warm stalled
    r=$(run "$mode")
    warm=${r% *}
    stalled=${r#* }
    [ "$stalled" -lt 3000 ] \
        || { echo "FAIL: with a $mode-stalled ping a cached request took ${stalled}ms" >&2; exit 1; }
    echo "  $mode: ${warm}ms with the peer quiet, ${stalled}ms behind an unfinished ping"
}

check once
check dribble

echo "kwddrain ok: a cached request is answered inside 3s behind a peer that has"
echo "  sent part of a message and stopped, and behind one dribbling it a byte at a time"
