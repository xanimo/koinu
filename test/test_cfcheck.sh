#!/usr/bin/env bash
# kw cfcheck reads a filter-header chain off a kwd socket and judges it.
#
# The judging is the point, so this drives it with canned replies rather than a
# real daemon: a served chain is checked against the filter-header anchors
# compiled into this release, and where two sources are given, against each
# other. A source that matches every anchor it covers is still one source above
# the last anchor, and cfcheck has to say so rather than implying agreement it
# did not get.
#
# Canned because nothing in the test tree serves BIP158 filters yet, so a real
# kwd here would answer "no filters" and none of the parsing or the anchor
# comparison would run. test_kwd.sh covers the refusal path against a real
# daemon; this covers what happens when one does answer.
set -eu
cd "$(dirname "$0")/.."

# test/cfstub rather than nc: the reply has to be exact, including shapes a real
# kwd would never send, and the connection has to close afterwards or kw waits
# out its receive timeout. nc can do that on linux and not on macos, where the
# gate failed for a reason that had nothing to do with the code under test.
[ -x ./test/cfstub ] || { echo "FAIL: test/cfstub is not built" >&2; exit 1; }

D=$(mktemp -d)
trap 'rm -rf "$D"; kill $(jobs -p) 2>/dev/null || true' EXIT

# The anchor this release pins at height 100000, straight out of chainparams.c,
# so the test fails if that table is edited without thinking about it.
# Scoped to the filter table: height 100000 is also a block-header checkpoint,
# and that array comes first in the file, so an unscoped match picks the block
# hash and the comparison fails for the wrong reason.
ANCHOR=$(awk '/KW_DOGE_MAINNET_CFCHECKPOINTS\[\] = \{/{f=1} f' crypto/chainparams.c |
         sed -n 's/.*{ *100000, *"\([0-9a-f]\{64\}\)" *}.*/\1/p' | head -1)
[ -n "$ANCHOR" ] || { echo "FAIL: no 100000 filter anchor in chainparams.c" >&2; exit 1; }

WRONG=$(printf '%s' "$ANCHOR" | tr '0-9a-f' '1-9a-f0')

# Serve one canned reply, then exit. cfstub prints "ready" once the socket is
# bound, so this waits on that rather than polling for the file to appear.
serve() {
    local sock=$1 body=$2
    exec 9< <(./test/cfstub "$sock" "$body")
    local line=""
    IFS= read -r -t 10 line <&9 || true
    [ "$line" = "ready" ] || { echo "FAIL: cfstub did not come up on $sock" >&2; exit 1; }
}

# 1. a chain that matches the anchor is accepted and says the anchor matched
serve "$D/a" "0 100000 1
100000 $ANCHOR
"
OUT=$(./kw cfcheck --daemon "$D/a" --since 100000 --count 1 2>&1) || true
case "$OUT" in
    *"1 anchor(s) in range matched"*) ;;
    *) echo "FAIL: a chain matching the anchor was not accepted:
$OUT" >&2; exit 1;;
esac
# and it must still say it only had one source
case "$OUT" in
    *"one source"*) ;;
    *) echo "FAIL: a single source did not say so:
$OUT" >&2; exit 1;;
esac

# 2. a chain that contradicts the anchor is refused, whatever else it claims
serve "$D/b" "0 100000 1
100000 $WRONG
"
if OUT=$(./kw cfcheck --daemon "$D/b" --since 100000 --count 1 2>&1); then
    echo "FAIL: a chain contradicting the anchor exited 0:
$OUT" >&2; exit 1
fi
case "$OUT" in
    *MISMATCH*) ;;
    *) echo "FAIL: no mismatch reported:
$OUT" >&2; exit 1;;
esac

# 3. two sources that disagree are caught, even where neither covers an anchor.
#    This is the case the anchors cannot settle and the only reason to ask twice.
serve "$D/c" "0 200001 1
200001 $ANCHOR
"
serve "$D/d" "0 200001 1
200001 $WRONG
"
if OUT=$(./kw cfcheck --daemon "$D/c" --daemon "$D/d" --since 200001 --count 1 2>&1); then
    echo "FAIL: two disagreeing sources exited 0:
$OUT" >&2; exit 1
fi
case "$OUT" in
    *DIVERGE*) ;;
    *) echo "FAIL: divergence not reported:
$OUT" >&2; exit 1;;
esac

# 4. a reply that promises more than it sends is refused rather than half read
serve "$D/e" "0 100000 4
100000 $ANCHOR
"
if OUT=$(./kw cfcheck --daemon "$D/e" --since 100000 --count 4 2>&1); then
    echo "FAIL: a short reply exited 0:
$OUT" >&2; exit 1
fi
case "$OUT" in
    *"promised 4 headers and sent 1"*) ;;
    *) echo "FAIL: a short reply was not named as such:
$OUT" >&2; exit 1;;
esac

# 5. a refusal from the daemon is passed through, not treated as a chain
serve "$D/f" "2 no filters here
"
if OUT=$(./kw cfcheck --daemon "$D/f" --since 100000 --count 1 2>&1); then
    echo "FAIL: a refusal exited 0:
$OUT" >&2; exit 1
fi
case "$OUT" in
    *"refused"*) ;;
    *) echo "FAIL: a refusal was not reported:
$OUT" >&2; exit 1;;
esac

# 6. --filters: the filters a source hands over have to hash into the chain it
#    served, header(i) = step(hash256(filter_i), header(i-1)). The values here
#    are computed from the BIP158 vectors in test/bip158_vectors.h, so this is
#    a real chain over real filters rather than three numbers that agree with
#    each other.
PREV=0000000000000000000000000000000000000000000000000000000000000000
H0=403b54aed3d4561d8098ecc7552d040a210347639c5ae08bd077af2ab51cffb4
H1=8a6f9ee6ed46f4c06fdf07bb96e126f03d84840329702579fc40c2c6d370ccb3
F0=43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000
F1=0000000000000000000000000000000000000000000000000000000000000000

#    cfcheck asks for the range, then the header below it, then the filters, so
#    the stub answers three times in that order. One cfstub per connection.
#    one bind, three connections: cfcheck reconnects for each request, and a
#    stub that rebound between them raced the next connect.
seq_serve() {
    local sock=$1; shift
    exec 8< <(./test/cfstub "$sock" "$@")
    local line=""
    IFS= read -r -t 10 line <&8 || true
    [ "$line" = "ready" ] || { echo "FAIL: cfstub did not come up on $sock" >&2; exit 1; }
}

seq_serve "$D/g" "0 2 2
2 $H0
3 $H1
" "0 1 1
1 $PREV
" "0 2 2
2 $F0
3 $F1
"
OUT=$(./kw cfcheck --daemon "$D/g" --since 2 --count 2 --with-filters 2>&1) || true
case "$OUT" in
    *"2 filter(s) hash into the chain"*) ;;
    *) echo "FAIL: real filters did not bind to their chain:
$OUT" >&2; exit 1;;
esac

# 7. a filter that is not the one the chain commits to is caught, even though
#    the chain itself is internally consistent and would pass on its own
seq_serve "$D/h" "0 2 2
2 $H0
3 $H1
" "0 1 1
1 $PREV
" "0 2 2
2 $F1
3 $F0
"
if OUT=$(./kw cfcheck --daemon "$D/h" --since 2 --count 2 --with-filters 2>&1); then
    echo "FAIL: swapped filters passed the binding check:
$OUT" >&2; exit 1
fi
case "$OUT" in
    *UNBOUND*) ;;
    *) echo "FAIL: an unbound filter was not named:
$OUT" >&2; exit 1;;
esac


echo "cfcheck ok: a chain is held to the compiled-in anchors, a contradicting one
  refused, two sources compared where no anchor can settle it, a short reply
  and a daemon refusal both caught, and filters checked against the chain
  they were served with, with a swapped pair rejected"
