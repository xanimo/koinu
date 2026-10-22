/* koinu.dog - the utxo set's layout, for this project's own code
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Not a public header and not installed. kw_utxoset is opaque in utxo.h because
 * it owns a growing array and a transaction per entry, so a caller holding one
 * by value has an object whose size the library is free to change under it.
 *
 * kw_utxo is public and stays a plain record: a caller reads an entry's value
 * and script, and kw_utxoset_at hands one out. */

#ifndef KOINU_UTXO_INTERNAL_H
#define KOINU_UTXO_INTERNAL_H

#include "utxo.h"

struct kw_utxoset {
    kw_utxo *u; size_t count, cap; uint64_t total;
    const kw_utxo_watcher *watch;        /* NULL unless a caller is keeping a record */
};

#endif /* KOINU_UTXO_INTERNAL_H */
