#!/usr/bin/env bash
# The signing half must not reference a socket call.
#
# The threat model says no run of kw that holds a secret opens a socket, and
# that is enforced per command because kw links the p2p parsers whether a given
# invocation uses them or not. This is the stronger form for anyone linking the
# library: libkoinu-sign.a holds the keys, the derivations, the share formats,
# the keystore, the transaction builder and the psbt code, and references no
# function that can open a connection, so the code that reads a peer's bytes
# cannot be in a signing process at all.
#
# Checked on the archive's undefined symbols rather than on the source, because
# that is what the linker will pull in: a call added through a macro, an inline
# function or a new dependency shows up here whether or not it is spelled out in
# a file under crypto/.
set -eu
cd "$(dirname "$0")/.."

command -v nm >/dev/null 2>&1 || { echo "split skipped: no nm"; exit 0; }

make -s split

SOCKETS='socket|socketpair|connect|bind|listen|accept|accept4|send|sendto|sendmsg|recv|recvfrom|recvmsg|getaddrinfo|gethostbyname|gethostbyname2|getnameinfo|setsockopt|getsockopt|shutdown|select|pselect|poll|ppoll|epoll_create|epoll_create1|epoll_ctl|epoll_wait'

# Undefined symbols only: a definition inside the archive is this project's own
# code. Two spellings have to be normalised away first, or the pattern below
# matches nothing and the check passes without checking anything: glibc puts a
# version suffix on a reference, and Mach-O prefixes every symbol with an
# underscore. -u rather than --undefined-only, which BSD nm does not take.
undef() {
    nm -u "$1" 2>/dev/null | awk '{print $NF}' | sed 's/@.*//; s/^_//' | sort -u
}

BAD=$(undef libkoinu-sign.a | grep -xE "($SOCKETS)" || true)
if [ -n "$BAD" ]; then
    echo "FAIL: libkoinu-sign.a references socket calls:" >&2
    echo "$BAD" | sed 's/^/  /' >&2
    echo "  the signing half is meant to be linkable without the p2p code" >&2
    exit 1
fi

# The control. If the chain half references none of these either, then either
# nm said nothing or the pattern does not match this platform's spelling, and
# the check above proved nothing.
GOOD=$(undef libkoinu-chain.a | grep -xE "($SOCKETS)" || true)
if [ -z "$GOOD" ]; then
    echo "FAIL: libkoinu-chain.a references no socket call, so the check above" >&2
    echo "  proved nothing. nm reported $(undef libkoinu-chain.a | wc -l | tr -d ' ')" >&2
    echo "  undefined symbols; a sample:" >&2
    undef libkoinu-chain.a | head -5 | sed 's/^/    /' >&2
    exit 1
fi

# and a signer that links against the signing half alone has to build and run,
# which is the claim the symbol check only approximates: a dependency from
# crypto/ or wallet/ onto net/ is a link error here rather than a grep miss
make -s test/signonly >/dev/null
./test/signonly >/dev/null || { echo "FAIL: the signing-only program did not run" >&2; exit 1; }

NG=$(printf '%s\n' "$GOOD" | wc -l | tr -d ' ')
SIGNSZ=$(wc -c < libkoinu-sign.a)
CHAINSZ=$(wc -c < libkoinu-chain.a)
echo "split ok: libkoinu-sign.a references no socket call and a signer links"
echo "  against it alone; libkoinu-chain.a references $NG of them."
echo "  $SIGNSZ bytes signing, $CHAINSZ bytes chain"
