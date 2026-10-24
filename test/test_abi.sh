#!/usr/bin/env bash
# What the soname promises, checked against the .so rather than against the
# headers.
#
# docs/abi.md says the exported set is kw_ and KW_ and nothing else, that the
# soname is libkoinu-sign.so.$KW_ABI whatever the release version is, and that
# secp256k1 is inside the library without being re-exported. Each of those is a
# property of the linked object, so each is read back off it here: a dropped
# version script, a forgotten -soname, or a vendored symbol that escaped the
# prefixing all show up as a difference in nm output, not as a compile error.
#
# Linux only. ld64 takes -exported_symbols_list rather than a version script,
# and the equivalent of readelf -d is otool -l, so the shapes differ enough that
# writing the macos half blind would be worse than skipping it. Not done.
set -eu
cd "$(dirname "$0")/.."

# The archive's build flags, passed in by the Makefile. Under make asan the .so
# is sanitized, and a consumer linked without -fsanitize puts libasan second in
# the initial library list, which ASan refuses to start under. Same reason
# test_install.sh takes them.
CONSUMER_CFLAGS=${1:--std=gnu11 -O1}

# The Makefile decides, by probing the linker, not this script by guessing from
# which tools are installed: the macos runner has a readelf and no -soname, so
# checking for the tool skipped nothing and the build failed mid-link.
#
# Passed in as $2 where the caller already knows, because asking again from here
# means a third make, and under make asan that query came back empty and this
# gate skipped itself for weeks while the run still reported success. A query
# that fails is not an answer: only the literal yes and no are, and anything
# else stops the run rather than quietly becoming "no shared library".
SHARED_OK=${2:-}
if [ -z "$SHARED_OK" ]; then
    SHARED_OK=$(make -s shared-ok 2>&1) || {
        echo "FAIL: could not ask the Makefile whether a shared library builds here." >&2
        echo "  make -s shared-ok exited $?, saying:" >&2
        echo "$SHARED_OK" | sed 's/^/    /' >&2
        exit 1
    }
fi
case "$SHARED_OK" in
    yes) ;;
    no)  echo "abi skipped: no shared library on this linker"; exit 0 ;;
    *)   echo "FAIL: shared-ok answered neither yes nor no, so the skip below" >&2
         echo "  would have been a guess. It said:" >&2
         echo "$SHARED_OK" | sed 's/^/    /' >&2
         exit 1 ;;
esac
command -v nm >/dev/null 2>&1 || { echo "abi skipped: no nm"; exit 0; }
command -v readelf >/dev/null 2>&1 || { echo "abi skipped: no readelf"; exit 0; }

make -s shared

VER=$(sed -n 's/.*KW_VERSION "\([^"]*\)".*/\1/p' include/kw_version.h)
ABI=$(sed -n 's/^KW_ABI *= *//p' Makefile)
[ -n "$VER" ] || { echo "FAIL: no version in include/kw_version.h"; exit 1; }
[ -n "$ABI" ] || { echo "FAIL: no KW_ABI in Makefile"; exit 1; }

fail() { echo "FAIL: $*"; exit 1; }

for half in sign chain; do
    so="libkoinu-$half.so.$VER"
    [ -f "$so" ] || fail "$so was not built"

    # the soname carries the abi number, not the release version: a consumer
    # linked today keeps working across 0.4.1 and 0.5.0
    got=$(readelf -d "$so" | sed -n 's/.*Library soname: \[\(.*\)\].*/\1/p')
    want="libkoinu-$half.so.$ABI"
    [ "$got" = "$want" ] || fail "$so soname is '$got', want '$want'"

    # the symlink chain a consumer's -lkoinu-$half resolves through
    [ "$(readlink "libkoinu-$half.so")" = "libkoinu-$half.so.$ABI" ] \
        || fail "libkoinu-$half.so does not point at the soname"
    [ "$(readlink "libkoinu-$half.so.$ABI")" = "$so" ] \
        || fail "libkoinu-$half.so.$ABI does not point at $so"

    # Exactly the promised set. Dynamic symbols only: a local definition is not
    # something a consumer can reach or this project has promised.
    extra=$(nm -D --defined-only "$so" | awk '{print $3}' | grep -vE '^(kw_|KW_)' || true)
    [ -z "$extra" ] || fail "$so exports names outside kw_/KW_:
$extra"

    n=$(nm -D --defined-only "$so" | awk '{print $3}' | grep -cE '^(kw_|KW_)')
    [ "$n" -gt 0 ] || fail "$so exports nothing, so the check above was vacuous"
    echo "  $so: soname $want, $n exported"
done

# secp256k1 is linked in and not re-exported. Both halves of that matter: if it
# were absent the .so would not load, and if it were exported a consumer linking
# its own copy would get two in one process with no warning.
nm -D --defined-only libkoinu-sign.so."$VER" | grep -q secp256k1 \
    && fail "libkoinu-sign re-exports secp256k1"
nm libkoinu-sign.so."$VER" 2>/dev/null | grep -qE ' [tT] secp256k1_ec_pubkey_create' \
    || fail "libkoinu-sign does not carry secp256k1 at all"
echo "  secp256k1 is inside libkoinu-sign and not on its exported list"

# chain against sign by soname, not by path
readelf -d libkoinu-chain.so."$VER" | grep -q "Shared library: \[libkoinu-sign.so.$ABI\]" \
    || fail "libkoinu-chain does not link libkoinu-sign by its soname"

# And it runs: the consumer is the same one test_install.sh compiles, linked
# dynamically here. A .so that resolves at link time and dies at load time
# would pass every check above.
D_TMP=$(mktemp -d)
trap 'rm -rf "$D_TMP"' EXIT
make -s install DESTDIR="$D_TMP" PREFIX=/usr >/dev/null
# shellcheck disable=SC2086
cc $CONSUMER_CFLAGS -I"$D_TMP/usr/include" -o "$D_TMP/consumer" test/consumer.c \
   -L"$D_TMP/usr/lib" -lkoinu-sign -pthread
out=$(LD_LIBRARY_PATH="$D_TMP/usr/lib" "$D_TMP/consumer")
case "$out" in
    *"consumer ok"*) ;;
    *) fail "the dynamically linked consumer did not run:
$out" ;;
esac
# the binary must actually have taken the .so, not quietly fallen back to the .a
readelf -d "$D_TMP/consumer" | grep -q "Shared library: \[libkoinu-sign.so.$ABI\]" \
    || fail "the consumer linked the archive, so nothing above was tested at run time"
echo "  a consumer runs against libkoinu-sign.so.$ABI"

echo "abi ok: both sonames carry KW_ABI=$ABI, only kw_/KW_ is exported, secp256k1"
echo "  is linked in and hidden, and a dynamically linked consumer runs"
