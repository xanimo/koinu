/* dogewallet - Dogecoin network parameters
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Values from Dogecoin Core src/chainparams.cpp. Test and regtest share the
 * p2sh, ext-key and coin-type constants and differ only in p2pkh and wif. */

#include "chainparams.h"

const dw_chainparams DW_DOGE_MAINNET = {
    "dogecoin",  0x1e, 0x16, 0x9e,
    { 0x02fac398, 0x02facafd }, 3,
    0xc0c0c0c0, 22556
};

const dw_chainparams DW_DOGE_TESTNET = {
    "dogecoin-testnet", 0x71, 0xc4, 0xf1,
    { 0x04358394, 0x043587cf }, 1,
    0xfcc1b7dc, 44556
};

const dw_chainparams DW_DOGE_REGTEST = {
    "dogecoin-regtest", 0x6f, 0xc4, 0xef,
    { 0x04358394, 0x043587cf }, 1,
    0xfabfb5da, 18444
};
