#!/usr/bin/env bash
# Pull a slice of a published filter cache into a local one.
#
# A cache is three files: cf.filters is a 4-byte tag then one record per block,
# cf.filters.idx is an 8-byte size then a uint64 file offset per record, and
# cf.filters.fh is the producer's verified chain tip. The index is a flat array,
# so a height maps to a byte range by arithmetic alone:
#
#     idx offset for height h = 8 + (h - base) * 8
#
# Read two of those offsets and you have the byte span of the records between
# them. Three range requests and no server logic: object storage with Range is
# the whole mechanism, which is why any mirror will do and none has to be
# trusted. What makes an untrusted mirror safe is on the other side:
#
#     kw cfcheck --daemon SOCK --since H --with-filters
#
# checks the slice against the filter-header anchors this release compiles in,
# and refuses the first filter that does not reproduce its own header.
#
# curl rather than anything in this tree on purpose. Object storage is https and
# koinu has no TLS, should not grow one, and libkoinu-sign.a references no socket
# call at all: test/test_split.sh fails the build if that changes. Fetching is a
# separate step that writes a file, exactly as kw sweep was split so the half
# holding keys opens no socket.
#
#     cfpull.sh BASE_URL FROM COUNT OUT [CACHE_BASE]
#
# BASE_URL    where cf.filters and cf.filters.idx live, no trailing slash
# FROM        first block height wanted
# COUNT       how many
# OUT         local cache to write, e.g. slice.filters
# CACHE_BASE  height of the published cache's first record, default 1
#
# Feed the result to kwd with --filters OUT --filters-base FROM.
set -eu

[ $# -ge 4 ] || { echo "usage: cfpull.sh BASE_URL FROM COUNT OUT [CACHE_BASE]" >&2; exit 2; }
BASE_URL=${1%/}
FROM=$2
COUNT=$3
OUT=$4
CACHE_BASE=${5:-1}

command -v curl >/dev/null 2>&1 || { echo "cfpull: needs curl" >&2; exit 1; }
command -v od   >/dev/null 2>&1 || { echo "cfpull: needs od" >&2; exit 1; }

# Per-object overrides, so this works against a bucket that hands out signed
# urls per object as well as a plain public mirror. The signature is part of the
# query string, so one base url cannot cover both files.
IDX_URL=${KW_CF_IDX_URL:-$BASE_URL/cf.filters.idx}
FIL_URL=${KW_CF_URL:-$BASE_URL/cf.filters}

[ "$FROM" -ge "$CACHE_BASE" ] || {
    echo "cfpull: height $FROM is below the cache's first record at $CACHE_BASE" >&2; exit 1; }
[ "$COUNT" -ge 1 ] || { echo "cfpull: COUNT must be 1 or more" >&2; exit 1; }

# One 8-byte index entry, as a decimal file offset. The index stores little
# endian, and od -j seeks without reading what it skips.
idx_at() {
    local i=$1
    local at=$(( 8 + i * 8 ))
    local hex
    # -L because object storage redirects http to https, and a 302 with no body
    # reads as a short index entry rather than as the redirect it is
    hex=$(curl -sSL --fail -r "$at-$(( at + 7 ))" "$IDX_URL" \
          | od -An -tx1 -v | tr -d ' \n')
    [ ${#hex} -eq 16 ] || { echo "cfpull: short index read at entry $i" >&2; exit 1; }
    # little endian to decimal, high byte first after reversing
    local be="" j
    for j in 7 6 5 4 3 2 1 0; do
        be="$be${hex:$((j*2)):2}"
    done
    printf '%d\n' "0x$be"
}

first=$(( FROM - CACHE_BASE ))
last=$(( first + COUNT ))

START=$(idx_at "$first")
END=$(idx_at "$last")
[ "$END" -gt "$START" ] || { echo "cfpull: empty or reversed span" >&2; exit 1; }

echo "cfpull: heights $FROM..$(( FROM + COUNT - 1 )), bytes $START..$(( END - 1 )) ($(( END - START )) bytes)"

# The tag, then the records. A cache is exactly that, so the slice is a cache in
# its own right and kwd will serve it given --filters-base.
printf 'KWF1' > "$OUT"
curl -sSL --fail -r "$START-$(( END - 1 ))" "$FIL_URL" >> "$OUT"

got=$(( $(wc -c < "$OUT") - 4 ))
[ "$got" -eq $(( END - START )) ] || {
    echo "cfpull: wanted $(( END - START )) bytes of records, got $got" >&2; exit 1; }

echo "cfpull: wrote $OUT, $(wc -c < "$OUT") bytes"
echo "cfpull: serve with  kwd --filters $OUT --filters-base $FROM"
echo "cfpull: check with  kw cfcheck --daemon SOCK --since $(( FROM + 1 )) --with-filters"
echo "cfpull: nothing here verified anything. The anchors do that, on the far side."
