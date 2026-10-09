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

/* A filter-header anchor: the BIP157 basic-filter header at a height, display
   (reversed) hex. Each filter header is sha256d(filter_hash || previous), so one
   value commits to every filter beneath it. That is what makes a single anchor
   worth carrying: compact filters are served by too few nodes to compare peers
   against each other, and without an anchor the chain's base is whatever the
   first peer to answer claimed it was. */
typedef struct { uint32_t height; const char *header; } kw_cfcheckpoint;

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
    uint32_t         genesis_time;  /* its timestamp and nBits, which the retarget */
    uint32_t         genesis_bits;  /* rule needs for the first period of the chain */
    uint32_t         pow_limit_bits;   /* the easiest target this network accepts */
    uint32_t         bip66_height;     /* base version 3 from here, DER signatures */
    uint32_t         bip65_height;     /* base version 4 from here, CHECKLOCKTIMEVERIFY */
    int              strict_chain_id;  /* core's fStrictChainId: off on testnet */
    uint32_t         maturity_switch;  /* the height nCoinbaseMaturity changes at */
    uint32_t         maturity_below;   /* confirmations a coinbase below it needs */
    uint32_t         maturity_from;    /* and from it on */
    const kw_checkpoint *checkpoints;  /* ascending by height, [0] is genesis; NULL if none */
    size_t           ncheckpoints;
    const char *const *dns_seeds;      /* seeder hostnames; NULL if none */
    size_t           nseeds;
    const kw_cfcheckpoint *cfcheckpoints;  /* ascending by height; NULL if none */
    size_t           ncfcheckpoints;
} kw_chainparams;

/* The confirmations a coinbase mined at (height) needs before it can be spent.
   Core carries nCoinbaseMaturity in the consensus parameters and picks the set by
   the coin's own height, so one constant is wrong on two thirds of the chain. */
uint32_t kw_coinbase_maturity(const kw_chainparams *cp, uint32_t height);

extern const kw_chainparams KW_DOGE_MAINNET;
extern const kw_chainparams KW_DOGE_TESTNET;
extern const kw_chainparams KW_DOGE_REGTEST;

#endif /* KOINU_CHAINPARAMS_H */
