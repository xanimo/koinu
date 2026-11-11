/* koinu.dog - extending the compiled-in filter-header anchors
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Everything at or below the newest anchor in chainparams is pinned by a hash
 * in this binary. Above it one peer's word decides, and that span grows with
 * the chain from the moment a release is cut. On a desktop it is bounded by how
 * often you update and by refusing to serve what nothing has checked; on a
 * phone, where installs lag releases by months and fetching the span as whole
 * blocks is not possible, it is the span that matters most.
 *
 * This is the rule a fetched table would have to satisfy before any of it could
 * be believed. Nothing calls it yet, and that is deliberate: shipping the rule
 * before the fetch means adding one later is a data change rather than a trust
 * change, and the trust change is the part that cannot be walked back after a
 * release.
 *
 * The rule, in one line: the compiled table is never discarded, a candidate may
 * only add heights above the newest compiled anchor, and one disagreement at a
 * height both hold rejects the whole candidate.
 *
 * What that bounds. A signing key held by whoever publishes such a table can
 * lie about the span above the newest anchor, which is exactly what a lying
 * peer can already do there, so the key buys an attacker nothing they did not
 * have. It cannot rewrite history, because every height the binary pins is
 * checked and a contradiction is fatal rather than preferred. An old install
 * with no network keeps its floor. */

#ifndef KOINU_CFANCHORS_H
#define KOINU_CFANCHORS_H

#include <stddef.h>
#include <stdint.h>

#include "chainparams.h"

/* Hashes in internal byte order, as the chain code holds them, rather than the
   display hex chainparams uses: a parsed table is bytes off a wire and nothing
   should have to re-reverse it to compare. */
typedef struct { uint32_t height; uint8_t header[32]; } kw_cfanchor;

/* No release will carry anywhere near this many. It exists so a length field
   off a wire cannot ask for an allocation, since the caller sizes its array
   from the count this returns. */
#define KW_CFANCHORS_MAX 65536

/* Serialized form:
 *
 *     "KWCA"          4   tag
 *     version         1   = 1
 *     reserved        3   must be zero
 *     network magic   4   little-endian, the chainparams magic
 *     count           4   little-endian
 *     then count x { height 4 LE ; header 32 }
 *
 * The network magic is in it because a mainnet table fed to a testnet client
 * would otherwise be a table of heights that happen to parse. Returns the
 * number of anchors written, or -1 on a tag, version, magic, count or length
 * this does not accept, or on heights that are not strictly ascending. */
long kw_cfanchors_parse(const uint8_t *buf, size_t buflen, uint32_t magic,
                        kw_cfanchor *out, size_t cap);

/* Whether (cand) may extend (cp)'s compiled anchors, and from which height its
 * entries start being new. Returns 1 and sets (*from_height) to the first
 * candidate height above the newest compiled anchor, or 0 with a reason logged.
 *
 * Requires an overlap: at least one height both tables hold, agreeing. Without
 * one a candidate is a list of hashes for heights this binary knows nothing
 * about, and accepting it would be trusting the fetch entirely rather than
 * checking it against something. Agreeing about the past is the only evidence
 * available that a table is about this chain.
 *
 * A candidate entry at or below the newest compiled anchor adds nothing, since
 * the compiled table stands either way, and is ignored unless it contradicts.
 * Omitting one is not a contradiction: regenerating drops the previous run's
 * tip entry, which is a height no multiple of the spacing lands on. */
int kw_cfanchors_extends(const kw_chainparams *cp, const kw_cfanchor *cand, size_t n,
                         uint32_t *from_height);

#endif /* KOINU_CFANCHORS_H */
