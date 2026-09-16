# Security

koinu handles private keys and spends money. If you find a way to lose either, or a
way to make it report something untrue about a chain or a balance, report it to
bluezr@dogecoin.com, PGP `00D7BCFF57782D5D91D6281A0DC64171D69D92F4`, which is the
same key that signs the release tags. Encrypt anything you would not put in a
public issue, and do not open a GitHub issue for a bug that costs someone money
until it is fixed.

A source archive carries no git history, so that key claim cannot be checked from
one. From a clone it can:

    git tag -v v0.2.5

which prints `Good signature` and the fingerprint above, or fails. Check it before
trusting either the code or this address.

Expect an acknowledgement within three days that a human has read it, and after
that whatever the fix actually needs, since a report with a reproduction gets one
faster than a report without. There is no bounty. If you do not hear back in a
week, assume the mail went astray and say so publicly without the details.

What counts is anything that loses money, exposes a key or a seed, or makes the
wallet believe something false about the chain. A wrong balance counts: a wallet
that under-reports what it holds is as wrong as one that over-reports, and one that
shows a payment that did not happen is worse than both. So does anything that
contradicts docs/threat-model.md, which is deliberately explicit about what is not
defended, because if the code does not do what that file says then the gap is a bug
in one of them and worth reporting either way. Denial of service against a wallet
you run yourself is worth reporting but is not urgent, and getting a node to stop
answering is the node's problem.

docs/threat-model.md also lists what this does not defend against, and a release
does not close those quietly, so a report restating a line from that file will get
a pointer back to it rather than a fix.

The suite is `make check`, `make asan`, `make tsan` and `make fuzz-asan`. A report
that comes with a failing case in that shape is one that cannot be argued with, and
it will be kept as a regression test with the reporter credited unless they would
rather not be.
