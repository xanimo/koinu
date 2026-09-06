/* koinu.dog - Dogecoin network parameters
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#ifndef KOINU_CHAINPARAMS_H
#define KOINU_CHAINPARAMS_H

#include <stdint.h>

#include "bip32.h"

/* The base58 version bytes and derivation constants for a network, from
   Dogecoin Core's chainparams.cpp. */
typedef struct {
    const char      *name;
    uint8_t          p2pkh;      /* PUBKEY_ADDRESS */
    uint8_t          p2sh;       /* SCRIPT_ADDRESS */
    uint8_t          wif;        /* SECRET_KEY     */
    kw_bip32_version bip32;      /* EXT_SECRET_KEY / EXT_PUBLIC_KEY */
    uint32_t         bip44_coin; /* SLIP-44 coin type */
    uint32_t         magic;      /* p2p message-start bytes */
    uint16_t         p2p_port;   /* default p2p port */
} kw_chainparams;

extern const kw_chainparams KW_DOGE_MAINNET;
extern const kw_chainparams KW_DOGE_TESTNET;
extern const kw_chainparams KW_DOGE_REGTEST;

#endif /* KOINU_CHAINPARAMS_H */
