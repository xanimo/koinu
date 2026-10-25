#!/usr/bin/env bash
# Publish a local filter cache as a dated snapshot, with a manifest.
#
# The counterpart to cfpull.sh. A published cache is the same three files kwd
# keeps, laid out under one prefix per snapshot:
#
#     <PREFIX>/<DATE>-<TIP>/cf.filters      the records
#     <PREFIX>/<DATE>-<TIP>/cf.filters.idx  the offset array cfpull ranges into
#     <PREFIX>/<DATE>-<TIP>/cf.filters.fh   the producer's verified chain tip
#     <PREFIX>/<DATE>-<TIP>/MANIFEST.txt    counts, sizes and sha256 of each
#
# Dated rather than overwritten, because a reader that fetched a slice an hour
# ago and a reader fetching one now should not silently be reading different
# bytes under the same url.
#
# Nothing here makes a snapshot trustworthy and it is not meant to. The reader
# checks it against the filter-header anchors the release compiles in:
#
#     kw cfcheck --daemon SOCK --since H --with-filters
#
# so a hostile or truncated mirror is caught on the far side by arithmetic, not
# here by provenance. The manifest records where the bytes came from so a human
# can judge that separately, which is a different question from whether they
# reproduce their own headers.
#
#     cfpush.sh STORE PREFIX [--public] [--s3cfg FILE] [--date YYYY-MM-DD]
#
# STORE     local cache, e.g. /var/lib/kwd/cf.filters
# PREFIX    destination, e.g. s3://dogecoin/mainnet/cfilters
# --public  grant anonymous read. Off by default: a prefix that becomes world
#           readable because a script assumed it should is the wrong default.
#
# Stop the producer first. A kwd appending to the store while this runs makes
# the manifest describe bytes that no longer exist, so the size is checked again
# at the end and a store that moved is a failure rather than a warning.
set -eu

[ $# -ge 2 ] || {
    echo "usage: cfpush.sh STORE PREFIX [--public] [--s3cfg FILE] [--date YYYY-MM-DD]" >&2
    exit 2
}
STORE=$1
PREFIX=${2%/}
shift 2

PUBLIC=0
S3CFG=${KW_S3CFG:-}
DATE=""
while [ $# -gt 0 ]; do
    case $1 in
        --public) PUBLIC=1; shift ;;
        --s3cfg)  S3CFG=${2:?--s3cfg needs a path}; shift 2 ;;
        --date)   DATE=${2:?--date needs YYYY-MM-DD}; shift 2 ;;
        *) echo "cfpush: unknown argument $1" >&2; exit 2 ;;
    esac
done

command -v s3cmd  >/dev/null 2>&1 || { echo "cfpush: needs s3cmd" >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "cfpush: needs sha256sum" >&2; exit 1; }

for f in "$STORE" "$STORE.idx" "$STORE.fh"; do
    [ -f "$f" ] || { echo "cfpush: $f is missing" >&2; exit 1; }
done
[ -n "$DATE" ] || DATE=$(date -u +%Y-%m-%d)

S3=(s3cmd)
[ -n "$S3CFG" ] && S3+=(-c "$S3CFG")

# The record count from the index, which is one uint64 per record after an
# 8-byte size, so the file length gives it without reading the cache.
idx_bytes=$(wc -c < "$STORE.idx")
count=$(( (idx_bytes - 8) / 8 ))
[ "$count" -ge 1 ] || { echo "cfpush: index holds no records" >&2; exit 1; }

# The sidecar's height, little endian at offset 4. That is the tip the producer
# verified, and it names the snapshot.
tip=$(od -An -tu8 -j4 -N8 -v < "$STORE.fh" | tr -d ' ')
case $tip in
    ''|*[!0-9]*) echo "cfpush: no tip height in the sidecar" >&2; exit 1 ;;
esac
[ "$tip" -ge 1 ] || { echo "cfpush: sidecar tip is $tip" >&2; exit 1; }

size_before=$(wc -c < "$STORE")
DEST="$PREFIX/$DATE-$tip"

echo "cfpush: $count records, tip $tip, $size_before bytes"
echo "cfpush: to $DEST"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
man=$tmp/MANIFEST.txt

{
    echo "koinu bip158 basic filter cache"
    echo
    echo "records      $count"
    echo "header tip   $tip"
    for f in "$STORE" "$STORE.idx" "$STORE.fh"; do
        printf '%-20s %14s bytes  sha256 %s\n' \
            "$(basename "$f")" "$(wc -c < "$f")" "$(sha256sum < "$f" | cut -d' ' -f1)"
    done
    echo
    echo "published $DATE by koinu cfpush from $(uname -s) $(uname -m)."
    echo
    echo "the .fh sidecar is required: koinu refuses a cache it cannot tie to a"
    echo "verified chain tip. check a slice of this against the anchors the release"
    echo "compiles in rather than trusting this file:"
    echo
    echo "    tools/cfpull.sh <BASE_URL> H COUNT slice.filters"
    echo "    kwd --filters slice.filters --filters-base H --socket SOCK"
    echo "    kw cfcheck --daemon SOCK --since \$((H + 1)) --with-filters"
} > "$man"

# The manifest last on purpose. It is what says the snapshot is complete and
# names the hashes, so a reader that finds it should find everything it hashes.
for f in "$STORE" "$STORE.idx" "$STORE.fh" "$man"; do
    args=(put "$f" "$DEST/$(basename "$f")")
    [ "$PUBLIC" = 1 ] && args+=(--acl-public)
    "${S3[@]}" "${args[@]}" >/dev/null
    echo "cfpush: put $(basename "$f")"
done

size_after=$(wc -c < "$STORE")
[ "$size_after" = "$size_before" ] || {
    echo "cfpush: $STORE grew from $size_before to $size_after during the upload," >&2
    echo "cfpush: so the manifest describes bytes this snapshot does not hold." >&2
    echo "cfpush: stop the producer and run it again." >&2
    exit 1
}

echo "cfpush: done. $DEST"
[ "$PUBLIC" = 1 ] && echo "cfpush: anonymous read is on for those four objects."
exit 0
