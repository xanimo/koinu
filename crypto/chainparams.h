/* koinu.dog - Dogecoin network parameters
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#ifndef KOINU_CHAINPARAMS_H
#define KOINU_CHAINPARAMS_H

#include <stdint.h>

#include "bip32.h"

/* A header-chain anchor: the block hash at a height, display (reversed) hex.
   Consecutive checkpoints bound the segments of the parallel header download;
   within a segment prev-linkage is verified and the last header must hash to
   the segment's end checkpoint. */
typedef struct { uint32_t height; const char *hash; } kw_checkpoint;

/* The base58 version bytes and derivation constants for a network, from
   Dogecoin Core's chainparams.cpp. */
typedef struct {
    const char      *name;
    uint8_t          p2pkh;      /* PUBKEY_ADDRESS */
    uint8_t          p2sh;       /* SCRIPT_ADDRESS */
    uint8_t          wif;        /* SECRET_KEY     */
    kw_bip32_version bip32;      /* EXT_SECRET_KEY / EXT_PUBLIC_KEY */
    uint32_t         bip44_coin; /* SLIP-44 coin type */
    uint32_t         magic;      /* p2p message-start bytes, little-endian */
    uint16_t         p2p_port;   /* default p2p port */
    const char      *genesis;    /* genesis block hash, display (reversed) hex */
    const kw_checkpoint *checkpoints;  /* ascending by height, [0] is genesis; NULL if none */
    size_t           ncheckpoints;
} kw_chainparams;

extern const kw_chainparams KW_DOGE_MAINNET;
extern const kw_chainparams KW_DOGE_TESTNET;
extern const kw_chainparams KW_DOGE_REGTEST;

#endif /* KOINU_CHAINPARAMS_H */
