/* koinu.dog - the signing half, as one header
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Everything in libkoinu-sign.a: keys, derivations, the two share-backup
 * formats, the keystore, transactions, psbt, and the wallet state that input
 * selection reads. None of it can open a socket, which test/test_split.sh
 * enforces by reading the archive's undefined symbols.
 *
 *     #include <koinu/koinu-sign.h>
 *     cc prog.c $(pkg-config --cflags --libs koinu-sign)
 *
 * The shared library carries the pinned secp256k1 inside it and does not export
 * it, so a program linking its own gets its own. Against the archive secp256k1
 * is yours to provide, which Libs.private says. This tree deliberately installs
 * no libsecp256k1 of its own, because a second one on a system is how a program
 * ends up with two and no warning.
 *
 * docs/abi.md is what libkoinu-sign.so.0 promises. In short: kw_tx, kw_psbt,
 * kw_utxoset, kw_watchset and kw_journal are handles whose contents move
 * without notice, and the records below that a caller declares by value have
 * their layout frozen for the life of the soname.
 *
 * What is stable in practice, because it is a standard rather than a decision
 * taken here: the BIP32/39/44 derivations, SLIP-39 and codex32 against their
 * own vectors, BIP174 psbt serialization, and the transaction signer, which is
 * byte-exact against libdogecoin's on 322 spends the network accepted. */

#ifndef KOINU_SIGN_H
#define KOINU_SIGN_H

#include "kw_version.h"

/* ── diagnostics ─────────────────────────────────────────────── */
/* Nothing here prints. Install a sink to see the few things the library has to
   say, such as a secret it could not lock into ram; without one it is silent,
   which is the default a library should have. */
#include "log.h"

/* ── the wallet ──────────────────────────────────────────────── */
#include "chainparams.h"      /* which network, and the heights its rules change at */
#include "keystore.h"         /* the seed sealed under argon2id and chacha20-poly1305 */
#include "bip39.h"            /* mnemonic <-> entropy, mnemonic -> seed */
#include "bip32.h"            /* extended keys and child derivation */
#include "bip44.h"            /* m/44'/coin'/account'/change/index */
#include "address.h"          /* p2pkh and p2sh, base58check */
#include "slip39.h"           /* shares as words, with a digest and a passphrase */
#include "codex32.h"          /* shares as base32, checkable by hand (BIP-93) */

/* ── spending ────────────────────────────────────────────────── */
#include "tx.h"               /* build, sign, serialize, sighash */
#include "psbt.h"             /* BIP174, the legacy subset dogecoin needs */
#include "utxo.h"             /* watched scripts and the tracked set */
#include "fee.h"              /* what a transaction of a given shape costs */
#include "change.h"           /* which change index a spend should use */
#include "journal.h"          /* what the set cannot remember: what has been spent */

/* ── primitives ──────────────────────────────────────────────── */
/* Here because a caller doing any of the above needs them, and because each is
   checked against published vectors. Not an invitation to reimplement the
   wallet out of them. */
#include "aead.h"
#include "base58.h"
#include "chacha20.h"
#include "ec.h"
#include "hex.h"
#include "hmac.h"
#include "kdf.h"
#include "mem.h"
#include "pbkdf2.h"
#include "ripemd160.h"
#include "rng.h"
#include "scrypt.h"
#include "sha2.h"
#include "siphash.h"

#endif /* KOINU_SIGN_H */
