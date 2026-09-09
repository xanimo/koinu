# Release Process

## Versioning

`KW_VERSION` in `cli/kw.c` is the only place the version is written down:

```c
#define KW_VERSION "0.2.1"
```

`kw --version` prints it. A tag must name the same version the binary reports,
so `v0.2.1` and `KW_VERSION "0.2.1"` go together or the release is wrong.

## Making a release

Two commits, in this order:

    docs: finalize changelog.md
    fixate 0.2.1

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

## Gates

Nothing is tagged until all of these pass on the commit being tagged:

    make check          29/29 suites
    make asan           exit 0, not just quiet output
    make fuzz-asan      the parsers under the sanitizers

CI runs all three on every push. A release also wants a live check against a
real node, since the offline suite has never caught a serialization bug on its
own: sync headers, scan a funded address, and confirm an outpoint.

## Tagging

Tags are signed. `tag.gpgSign` is set in the repository, so `git tag -a`
signs, but be explicit:

    git tag -s v0.2.1 -m "koinu v0.2.1"
    git push origin v0.2.1

GitHub shows an unsigned tag as `Unverified`, which is the check that the tag
came from the maintainer rather than from whoever could push. Verify before
pushing:

    git tag -v v0.2.1
