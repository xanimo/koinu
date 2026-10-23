/* koinu.dog - the journal's layout, for this project's own code
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Not a public header and not installed. kw_journal is opaque in journal.h
 * because the library owns the array; kw_journal_entry is public and stays a
 * plain record, since a caller both writes one and reads one back. */

#ifndef KOINU_JOURNAL_INTERNAL_H
#define KOINU_JOURNAL_INTERNAL_H

#include "journal.h"

struct kw_journal { kw_journal_entry *e; size_t count, cap; };

#endif /* KOINU_JOURNAL_INTERNAL_H */
