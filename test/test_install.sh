#!/usr/bin/env bash
# make install has to produce a tree a consumer can build against.
#
# Installs into a throwaway DESTDIR and compiles test/consumer.c with only the
# installed prefix on the include path. That is what catches a public header
# including a private one, a header the install forgot, or a pkg-config file
# naming the wrong directory, none of which show up when everything is still
# reachable from the source tree.
#
# secp256k1 comes from this tree, because install deliberately does not ship
# one: a second libsecp256k1 on a system is how a program links two of them.
set -eu
cd "$(dirname "$0")/.."

D=$(mktemp -d)
trap 'rm -rf "$D"' EXIT

make -s install DESTDIR="$D" PREFIX=/opt/koinu >/dev/null

for f in /opt/koinu/include/koinu/koinu-sign.h \
         /opt/koinu/lib/libkoinu-sign.a \
         /opt/koinu/lib/libkoinu-chain.a \
         /opt/koinu/lib/pkgconfig/koinu-sign.pc \
         /opt/koinu/bin/kw; do
    [ -e "$D$f" ] || { echo "FAIL: install did not produce $f" >&2; exit 1; }
done

# the .pc has to say where things actually are
if command -v pkg-config >/dev/null 2>&1; then
    export PKG_CONFIG_PATH="$D/opt/koinu/lib/pkgconfig"
    export PKG_CONFIG_SYSROOT_DIR="$D"
    CF=$(pkg-config --cflags koinu-sign)
    LB=$(pkg-config --libs koinu-sign)
    case "$CF" in *"/opt/koinu/include"*) ;; *) echo "FAIL: pkg-config cflags: $CF" >&2; exit 1;; esac
    case "$LB" in *-lkoinu-sign*) ;; *) echo "FAIL: pkg-config libs: $LB" >&2; exit 1;; esac
    # the static link line has to name secp256k1, since this project does not
    # install one and a consumer has to know that
    SL=$(pkg-config --static --libs koinu-sign)
    case "$SL" in *-lsecp256k1*) ;; *) echo "FAIL: static libs do not name secp256k1: $SL" >&2; exit 1;; esac
fi

# The flags the archive was built with, given as $1 by the check target.
#
# Under make asan the installed archive holds instrumented objects, and a
# consumer compiled without -fsanitize fails to link against the asan runtime.
# Passed at the call site rather than read from the environment because this
# Makefile says "override CFLAGS += ...", which makes it a makefile-defined
# variable and stops make exporting it to recipes even when it arrived on the
# command line. Running this script by hand gets the fallback, which is what an
# ordinary consumer would use against an ordinary build.
CONSUMER_CFLAGS=${1:--std=gnu11 -O1 -g -Wall -Wextra}

# Only the installed prefix. No -Icrypto, -Inet, -Iwallet or -Iinclude, and no
# -include of the vendored prefix header: if a public header needed any of
# those, this is where it says so.
# shellcheck disable=SC2086
cc $CONSUMER_CFLAGS \
   -I"$D/opt/koinu/include" \
   -o "$D/consumer" test/consumer.c \
   "$D/opt/koinu/lib/libkoinu-sign.a" \
   depends/secp256k1/.libs/libsecp256k1.a -pthread \
    || { echo "FAIL: a consumer could not build against the installed tree" >&2; exit 1; }

"$D/consumer" || { echo "FAIL: the consumer did not run" >&2; exit 1; }

# uninstall has to take back what it put there
make -s uninstall DESTDIR="$D" PREFIX=/opt/koinu >/dev/null
for f in /opt/koinu/include/koinu/koinu-sign.h /opt/koinu/lib/libkoinu-sign.a \
         /opt/koinu/lib/pkgconfig/koinu-sign.pc /opt/koinu/bin/kw; do
    [ ! -e "$D$f" ] || { echo "FAIL: uninstall left $f behind" >&2; exit 1; }
done

echo "install ok: headers, archives, pkg-config and binaries placed, a consumer"
echo "  built and run against the installed prefix alone, and uninstall took it back"
