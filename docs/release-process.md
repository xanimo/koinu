# Release Process

## Versioning

`KW_VERSION` in `cli/kw.c` is the only place the version is written down:

```c
#define KW_VERSION "0.2.3"
```

`kw --version` prints it. A tag must name the same version the binary reports,
so `v0.2.3` and `KW_VERSION "0.2.3"` go together or the release is wrong.

## Making a release

Two commits, in this order:

    docs: finalize changelog.md
    fixate 0.2.3

The changelog commit moves everything under `## [Unreleased]` into a new
`## [MAJOR.MINOR.PATCH] - YYYY-MM-DD` section, adds the compare link against
the previous tag, and leaves `## [Unreleased]` empty. The fixation commit is
the one line of `KW_VERSION`.

Entries are the commit subjects since the last tag:

    git log --reverse --format='* %s' vPREV..HEAD

koinu takes commits directly on main, so there are no pull requests for GitHub
to enumerate and `gh api repos/xanimo/koinu/releases/generate-notes` returns
only the compare link. The changelog is written by hand in the shape those
notes would take, minus the `by @author in <pr>` each bullet would carry. If
work starts arriving as pull requests, generate the notes and paste them
instead.

## Anchors

Two tables in `crypto/chainparams.c` say what a sync may take on trust, and both go
stale as the chain grows. Everything below the last anchor is trusted because a
compiled-in hash pins it; everything above it is the tail a client has to check the
slow way, so a release that ships old anchors ships a longer tail than it needs to.

Block-header anchors sit every 25000 heights. Sync a cache to the tip and print the
table:

    ./kw height --node HOST --headers main.kwh
    make gen_checkpoints && ./gen_checkpoints main.kwh

It writes the whole array to stdout and a summary to stderr, including how many
headers sit past the last anchor. Paste the array over
`KW_DOGE_MAINNET_CHECKPOINTS`. Run against an unchanged cache it reproduces the
committed table exactly, which is how to tell the generator still agrees with it.

Filter-header anchors sit every 100000 and need a peer that serves BIP157 filters,
which few do:

    ./kw cfcheckpoints --node HOST --headers main.kwh --since 100000

Paste that over `KW_DOGE_CFCHECKPOINTS`. A filter header commits to every filter
beneath it, so one anchor is worth carrying: compact filters are served by too few
nodes to compare peers against each other.

Neither table changes unless the chain has passed the next anchor height, and that
is the usual answer at these spacings. Regenerate anyway and diff, rather than
assuming: the point is that the tail is known, not that the file changed.

## Gates

Nothing is tagged until all of these pass on the commit being tagged:

    make check          43/43 suites
    make asan           exit 0, which now means what it says: the sanitized
                        builds carry -fno-sanitize-recover=undefined, so a
                        ubsan report ends the run instead of printing and
                        exiting 0
    make tsan           test_powq and test_psync only, which is the threaded
                        code: the validator pool and the parallel download
    make fuzz-asan      the in-tree corpus and 20000 mutations per target
                        under the sanitizers, which is replay rather than
                        coverage-guided
    make fuzz           libFuzzer, three binaries: fuzz_parse over the buffer
                        and file parsers, fuzz_socks5 over a real loopback
                        proxy, fuzz_kwd over the daemon's request line. At
                        least 10 minutes each; this is the one that finds
                        inputs the corpus does not have

The release binary's hardening is a property of the toolchain that linked it, so
check the artifact rather than the flags:

    readelf -d kw | grep -E 'BIND_NOW|FLAGS'      # BIND_NOW, NOW PIE
    readelf -lW kw | grep GNU_RELRO               # present
    objdump -d kw | grep -c endbr64               # nonzero on x86_64

The Makefile probes each flag against the compiler and drops what it cannot
take, so a toolchain without one builds quietly without it.

CI runs check, asan and fuzz-asan on every push, on x86_64 gcc and clang, i386, and
arm64. `make tsan` and `make fuzz` are not in CI and are run here. A release also wants a live check against a
real node, since the offline suite has never caught a serialization bug on its
own: sync headers, scan a funded address, and confirm an outpoint.

## Tagging

Tags are signed. `tag.gpgSign` is set in the repository, so `git tag -a`
signs, but be explicit:

    git tag -s v0.2.3 -m "koinu v0.2.3"
    git push origin v0.2.3

GitHub shows an unsigned tag as `Unverified`, which is the check that the tag
came from the maintainer rather than from whoever could push. Verify before
pushing:

    git tag -v v0.2.3
