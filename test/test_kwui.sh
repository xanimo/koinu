#!/usr/bin/env bash
# kwui smoke test. The TUI reads keys and draws frames, so it is driven the only
# way that proves anything: a fifo on its stdin, its screen captured to a file,
# and each frame waited for by what it must contain. No `timeout`, which macOS
# does not ship; the reader is bounded by a poll count instead, and the process is
# killed if it outlives the script.
set -eu
cd "$(dirname "$0")/.."

WORK=$(mktemp -d)
UI_PID=""
cleanup() {
    [ -n "$UI_PID" ] && kill "$UI_PID" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

printf 'a test passphrase\n' > "$WORK/pass"
OUT=$(./kw --regtest new --keystore "$WORK/ks" --passphrase "@$WORK/pass" --words 12)
ADDR=$(echo "$OUT" | awk '/first address/{print $3}')
[ -n "$ADDR" ] || { echo "FAIL: no address from kw new" >&2; exit 1; }

# the scriptPubKey for that address, so a utxo paying it can be written
SPK=$(./kw --regtest address --keystore "$WORK/ks" --passphrase "@$WORK/pass" --spk)
[ -n "$SPK" ] || { echo "FAIL: no scriptPubKey from kw address --spk" >&2; exit 1; }

TXID1=1111111111111111111111111111111111111111111111111111111111111111
TXID2=2222222222222222222222222222222222222222222222222222222222222222
printf '%s 0 500000000 100 %s\n' "$TXID1" "$SPK" > "$WORK/ks.utxos"

# A coin past kwui's --gap but inside what kw scan watched. kwui used to derive
# its own gap only, so this one was missing from the balance while send_flow
# still spent it and then failed at signing.
SPK25=$(./kw --regtest address --keystore "$WORK/ks" --passphrase "@$WORK/pass" --index 25 --spk)
TXID3=3333333333333333333333333333333333333333333333333333333333333333
printf '%s 0 900000000000 101 %s\n' "$TXID3" "$SPK25" >> "$WORK/ks.utxos"
printf 'feerate 0\ngap 30\n' > "$WORK/ks.utxos.meta"

# wait until (file) contains (pattern), or fail after ~10s
wait_for() {
    i=0
    while [ "$i" -lt 100 ]; do
        if grep -q "$2" "$1" 2>/dev/null; then return 0; fi
        i=$((i + 1))
        sleep 0.1
    done
    echo "FAIL: never saw '$2' on screen" >&2
    sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g' "$1" | tail -20 >&2
    exit 1
}

mkfifo "$WORK/in"
./kwui --regtest --keystore "$WORK/ks" --utxos "$WORK/ks.utxos" --gap 2 \
    < "$WORK/in" > "$WORK/out" 2>&1 &
UI_PID=$!
# read-write, so this never blocks: opening a fifo write-only waits for a
# reader, and if kwui died at startup that wait would hang the job instead of
# failing it
exec 3<> "$WORK/in"

printf 'a test passphrase\n' >&3
# 5 DOGE at index 0 plus 9000 at index 25, which is past --gap 2 and inside the
# extent the meta records
wait_for "$WORK/out" '9005.00000000 DOGE across 2'

printf '\n' >&3
wait_for "$WORK/out" 'receive address'                    # enter opened the address
wait_for "$WORK/out" "$ADDR"
printf 'q' >&3

printf 'c' >&3
wait_for "$WORK/out" 'unspent output'                     # the coins screen
printf 'q' >&3

printf 'h' >&3
wait_for "$WORK/out" 'nothing recorded yet'               # an empty journal says so
printf 'q' >&3

# a receive appended while it runs must appear on a refresh
printf '%s 1 250000000 101 %s\n' "$TXID2" "$SPK" >> "$WORK/ks.utxos"
printf 'r' >&3
wait_for "$WORK/out" '9007.50000000 DOGE across 3'

printf 'q' >&3
exec 3>&-
wait "$UI_PID" || { echo "FAIL: kwui exited non-zero" >&2; exit 1; }
UI_PID=""

echo "kwui ok: browse, address, coins, empty history, refresh picks up a new output,"
echo "  and a coin past --gap inside the scan's extent is counted"
