# Release Process

## Versioning

`KW_VERSION` in `include/kw_version.h` is the only place the version is written
down. `kw --version` prints it and the p2p user agent is built from it:

```c
#define KW_VERSION "0.2.5"
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

Filter-header anchors sit every 10000 and need a peer that serves BIP157 filters,
which few do:

    ./kw cfcheckpoints --node HOST --headers main.kwh --since 10000

Paste that over `KW_DOGE_MAINNET_CFCHECKPOINTS`. A filter header commits to every
filter beneath it, so one anchor is worth carrying: compact filters are served by
too few nodes to compare peers against each other.

They were every 100000 until the tail above the last one became the thing that
mattered. Filters come from one peer where headers come from three, so the span
above the newest anchor is a span one peer's word decides, and the anchored walk
replays every filter between a height and the anchor below it. At 100000 that
measured 1.9s for a one-header reply on mainnet and left 33000 blocks unpinned;
at 10000 it is 0.053s. 644 anchors rather than 64 is the cost.

Neither table changes unless the chain has passed the next anchor height, and that
is the usual answer at these spacings. Regenerate anyway and diff, rather than
assuming: the point is that the tail is known, not that the file changed.

The two diff differently, and the filter one looks wrong when it is not.
gen_checkpoints emits an anchor only at the multiples, so against a grown cache
it reproduces the committed table exactly and a difference means something is
wrong. kw cfcheckpoints also anchors the tip, so its last line is whatever the
tip was when it ran and differs every time the chain moves. At 0.5.0 that was
643 of 644 identical with the last entry 6432061 against a regenerated 6437155,
which is the expected answer and not a finding. Read the diff, do not count it.

## Gates

Nothing is tagged until all of these pass on the commit being tagged:

    make check          51/51 suites, which now ends with fuzz-syntax and
                        fuzz-run, so the harnesses compile in the fast loop
    make tools          the twelve hand-run diagnostics link; none are run
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
    make fuzz-net       eight stateful harnesses: a scripted fake peer per
                        exchange, over the handshake and recv, single and
                        multi-peer header sync, psync segments and the parallel
                        fill, cf header fetch with cfstore sync, spv block
                        sync, the outpoint range query, and kwd's request loop.
                        These carry invariants on the store, the caches and
                        every answer, which is what a crash-only run misses

`make fuzz` and `make fuzz-net` build; running the binaries is the gate. Run
each under `setarch -R`:

    setarch -R ./fz_spvsync -max_total_time=300 corpusdir

Without it, half the runs on this host die with SIGSEGV and an empty log before
libFuzzer prints a line. That is the sanitizer's shadow mapping colliding with
`vm.mmap_rnd_bits=32`, which is what Ubuntu 24.04 on 6.8 sets, not a finding:
six of twelve seeds crashed with randomization on and none of the same six with
it off. `sysctl vm.mmap_rnd_bits=28` fixes it host-wide if you have root. The
output is block buffered, so a run killed by a signal leaves nothing behind to
read, which is what makes this look like an early crash rather than a late one.

The release binary's hardening is a property of the toolchain that linked it, so
check the artifact rather than the flags:

    readelf -d kw | grep -E 'BIND_NOW|FLAGS'      # BIND_NOW, NOW PIE
    readelf -lW kw | grep GNU_RELRO               # present
    objdump -d kw | grep -c endbr64               # nonzero on x86_64

The Makefile probes each flag against the compiler and drops what it cannot
take, so a toolchain without one builds quietly without it.

CI runs `make check` and `make tools` across a matrix of x86_64 gcc, x86_64
clang, i386 and macos arm64, and `make asan` with `make fuzz-asan` in one ubuntu
job with the default compiler. The shared library is covered by
`test/test_abi.sh` inside `make check`, on the ELF platforms only: see the last
section of docs/abi.md. `make tsan` and `make fuzz` are not in CI and are run here. A release
also wants a live check against a real node, since the offline suite has never
caught a serialization bug on its own: sync headers, scan a funded address, and
confirm an outpoint.

## Tagging

Tags are signed. `tag.gpgSign` is set in the repository, so `git tag -a`
signs, but be explicit:

    git tag -s v0.2.3 -m "koinu v0.2.3"
    git push origin v0.2.3

GitHub shows an unsigned tag as `Unverified`, which is the check that the tag
came from the maintainer rather than from whoever could push. Verify before
pushing:

    git tag -v v0.2.3
