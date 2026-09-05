/* dogewallet - Dogecoin network parameters
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#ifndef DOGEWALLET_CHAINPARAMS_H
#define DOGEWALLET_CHAINPARAMS_H

#include <stdint.h>

#include "bip32.h"

/* The base58 version bytes and derivation constants for a network, from
   Dogecoin Core's chainparams.cpp. */
typedef struct {
    const char      *name;
    uint8_t          p2pkh;      /* PUBKEY_ADDRESS */
    uint8_t          p2sh;       /* SCRIPT_ADDRESS */
    uint8_t          wif;        /* SECRET_KEY     */
    dw_bip32_version bip32;      /* EXT_SECRET_KEY / EXT_PUBLIC_KEY */
    uint32_t         bip44_coin; /* SLIP-44 coin type */
} dw_chainparams;

extern const dw_chainparams DW_DOGE_MAINNET;
extern const dw_chainparams DW_DOGE_TESTNET;
extern const dw_chainparams DW_DOGE_REGTEST;

#endif /* DOGEWALLET_CHAINPARAMS_H */
