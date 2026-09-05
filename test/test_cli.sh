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
# insufficient inputs must fail
if ./kw --regtest sign --keystore "$WORK/ks" --passphrase "@$WORK/pass" \
       --input "$IN" --to "$ADDR1:20.0" --fee 0.001 >/dev/null 2>&1; then
    echo "FAIL: signed a spend the inputs cannot cover" >&2; exit 1
fi

echo "cli ok: new/address round trip, index varies, wrong passphrase and clobber refused, sign deterministic"
