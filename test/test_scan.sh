#!/usr/bin/env bash
# kw scan against a regtest node: the sync path end to end, and the one part of
# the journal no offline test can reach, since a receive is recorded only where a
# scan finds it. Pays two of the wallet's addresses from the node, scans, and
# checks both the utxo set and the journal. Scanning twice must not record a
# receive twice, which is the assertion that was previously code-reading only.
#
# Its own ports, so it cannot be skipped by test_sweep.sh's node still shutting
# down. Skips when dogecoind is absent, so make check stays hermetic.
set -eu
cd "$(dirname "$0")/.."

command -v dogecoind >/dev/null 2>&1 || { echo "scan skipped: no dogecoind"; exit 0; }
command -v dogecoin-cli >/dev/null 2>&1 || { echo "scan skipped: no dogecoin-cli"; exit 0; }
P2P=18544
RPC=18545
if (exec 3<>/dev/tcp/127.0.0.1/$P2P) 2>/dev/null; then
    exec 3>&- 2>/dev/null || true
    echo "scan skipped: port $P2P in use"; exit 0
fi

D=$(mktemp -d)
C="dogecoin-cli -regtest -datadir=$D -rpcport=$RPC"
cleanup() { $C stop >/dev/null 2>&1 || true; sleep 1; rm -rf "$D"; }
trap cleanup EXIT

dogecoind -regtest -datadir="$D" -port=$P2P -rpcport=$RPC -daemon >/dev/null 2>&1 \
    || { echo "scan skipped: dogecoind would not start"; exit 0; }
for _ in $(seq 1 20); do $C getblockcount >/dev/null 2>&1 && break; sleep 1; done
$C getblockcount >/dev/null 2>&1 || { echo "scan skipped: regtest node never came up"; exit 0; }

printf 'a test passphrase\n' > "$D/pass"
K="--keystore $D/ks --passphrase @$D/pass"
./kw --regtest new $K --words 12 >/dev/null
A0=$(./kw --regtest address $K --index 0)
A1=$(./kw --regtest address $K --index 1)
[ -n "$A0" ] && [ -n "$A1" ] || { echo "FAIL: no addresses derived" >&2; exit 1; }

# the node needs spendable coins before it can pay anyone
MINE=$($C getnewaddress)
$C generatetoaddress 101 "$MINE" >/dev/null
$C sendtoaddress "$A0" 10 >/dev/null
$C sendtoaddress "$A1" 5 >/dev/null
$C generatetoaddress 3 "$MINE" >/dev/null

U="$D/u"
J="$U.journal"
SCAN="./kw --regtest scan $K --node 127.0.0.1 --port $P2P --spv --gap 5 --utxos $U"

OUT=$($SCAN)
echo "$OUT"
BAL=$(echo "$OUT" | awk '/^scanned/{print $7}')
[ "$BAL" = "1500000000" ] || { echo "FAIL: scanned balance $BAL, want 1500000000" >&2; exit 1; }

NU=$(awk '!/^#/{n++} END{print n+0}' "$U")   # the file carries a header line
[ "$NU" = "2" ] || { echo "FAIL: utxo set has $NU entries, want 2" >&2; cat "$U" >&2; exit 1; }

# the journal is the point of this test: two receives, both named and confirmed
[ -f "$J" ] || { echo "FAIL: the scan recorded no journal at $J" >&2; exit 1; }
NJ=$(awk 'END{print NR}' "$J")
[ "$NJ" = "2" ] || { echo "FAIL: journal has $NJ entries, want 2" >&2; cat "$J" >&2; exit 1; }
awk '$2 != "in" { exit 1 }' "$J" || { echo "FAIL: a scanned receive is not an in entry" >&2; exit 1; }
awk '$5 < 1 { exit 1 }' "$J" || { echo "FAIL: a receive was recorded with no height" >&2; exit 1; }
grep -q "$A0" "$J" || { echo "FAIL: the journal does not name $A0" >&2; cat "$J" >&2; exit 1; }
grep -q "$A1" "$J" || { echo "FAIL: the journal does not name $A1" >&2; cat "$J" >&2; exit 1; }
TOT=$(awk '{s+=$6} END{print s}' "$J")
[ "$TOT" = "1500000000" ] || { echo "FAIL: journal totals $TOT, want 1500000000" >&2; exit 1; }

case $(ls -l "$J") in
    -rw-------*) ;;
    *) echo "FAIL: journal is $(ls -l "$J" | cut -c1-10), want -rw-------" >&2; exit 1;;
esac

# scanning again finds the same outputs and must not record them again
$SCAN >/dev/null
NJ2=$(awk 'END{print NR}' "$J")
[ "$NJ2" = "2" ] || { echo "FAIL: a second scan grew the journal to $NJ2" >&2; cat "$J" >&2; exit 1; }

# a third payment is recorded on the next scan, so dedup is not just "never add"
$C sendtoaddress "$A0" 2 >/dev/null
$C generatetoaddress 3 "$MINE" >/dev/null
$SCAN >/dev/null
NJ3=$(awk 'END{print NR}' "$J")
[ "$NJ3" = "3" ] || { echo "FAIL: a new receive did not append, journal has $NJ3" >&2; cat "$J" >&2; exit 1; }

echo "scan ok: 15 DOGE over 2 addresses found and journaled with heights, a rescan"
echo "  adds nothing, and a later payment appends"
