#!/bin/sh
# koinu.dog - kwd's socket, against a fake peer
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 bluezr
#
# kwd answers one request per connection from a single-threaded accept loop, so a
# client that connects and never speaks is the whole daemon's problem and not just
# its own. These check that it is not, and that the socket is never readable by
# anyone else.
set -e

WORK=$(mktemp -d)
trap 'kill $NODE_PID $KWD_PID 2>/dev/null; rm -rf "$WORK"' EXIT INT TERM

command -v nc >/dev/null 2>&1 || { echo "kwd skipped: no nc"; exit 0; }

./test/fakenode --regtest > "$WORK/port" &
NODE_PID=$!
i=0
while [ ! -s "$WORK/port" ]; do
    i=$((i + 1)); [ $i -gt 100 ] && { echo "FAIL: fakenode printed no port" >&2; exit 1; }
    sleep 0.1
done
PORT=$(cat "$WORK/port")

SOCK="$WORK/kwd.sock"
./kwd --regtest --node 127.0.0.1 --port "$PORT" --socket "$SOCK" \
      --filters "$WORK/filters" > "$WORK/kwd.log" 2>&1 &
KWD_PID=$!
i=0
while [ ! -S "$SOCK" ]; do
    i=$((i + 1)); [ $i -gt 150 ] && { echo "FAIL: kwd never listened" >&2; cat "$WORK/kwd.log" >&2; exit 1; }
    sleep 0.1
done

# the socket carries money decisions, so no other local user may reach it
MODE=$(ls -l "$SOCK" | cut -c1-10)
[ "$MODE" = "srw-------" ] || { echo "FAIL: socket is $MODE, want srw-------" >&2; exit 1; }

# a client that connects and says nothing must not hold the loop. nc keeps the
# connection open with no input; the request behind it has to be answered anyway.
sleep 3600 | nc -U "$SOCK" > /dev/null 2>&1 &
SILENT_PID=$!
sleep 0.5

START=$(date +%s)
REPLY=$(printf 'outpoint mfchMLScZtKtTR9SkQafyswfw3CLLccSwy 00000000000000000000000000000000000000000000000000000000000000ff:0 0\n' \
        | nc -w 20 -U "$SOCK" 2>/dev/null | head -1)
END=$(date +%s)
kill $SILENT_PID 2>/dev/null || true

[ -n "$REPLY" ] || { echo "FAIL: no reply while a silent client was connected" >&2; cat "$WORK/kwd.log" >&2; exit 1; }
# any rc is fine: the chain is empty so the answer is an error either way. What
# is being tested is that one arrived, and within the read timeout rather than
# after the silent client gave up.
ELAPSED=$((END - START))
[ "$ELAPSED" -le 20 ] || { echo "FAIL: reply took ${ELAPSED}s behind a silent client" >&2; exit 1; }

# the answer has to come from a chain whose work was checked. kwd used to sync
# headers with no validator pool at all, so it answered whether an outpoint was
# confirmed without checking that the chain behind it had any work.
grep -q "work-checked" "$WORK/kwd.log" || {
    echo "FAIL: kwd did not report checking any header work" >&2
    cat "$WORK/kwd.log" >&2; exit 1; }
# and with one --node it has to say that it compared nothing
grep -q "one peer, so nothing compares" "$WORK/kwd.log" || {
    echo "FAIL: a single-peer kwd did not say it compared nothing" >&2
    cat "$WORK/kwd.log" >&2; exit 1; }

# and a request with no newline is refused rather than waited on forever
TRUNC=$(printf 'outpoint no-newline-here' | nc -w 20 -U "$SOCK" 2>/dev/null | head -1 || true)
case "$TRUNC" in
    "1 request truncated or too slow") ;;
    "") echo "FAIL: a request with no newline got no reply" >&2; exit 1;;
    *)  echo "FAIL: unterminated request answered with '$TRUNC'" >&2; exit 1;;
esac

echo "kwd ok: socket is 0600, a silent client does not block the loop, an\n  unterminated request is refused, and the chain it answers from is work-checked"
