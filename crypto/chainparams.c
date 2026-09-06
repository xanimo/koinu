/* koinu.dog - Dogecoin network parameters
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * Values from Dogecoin Core src/chainparams.cpp. The magic is pchMessageStart
 * as a little-endian word, since proto.c serializes it that way: the on-wire
 * bytes are fc c1 b7 dc (test) and fa bf b5 da (regtest), not the reverse. */

#include "chainparams.h"

const kw_chainparams KW_DOGE_MAINNET = {
    "dogecoin",  0x1e, 0x16, 0x9e,
    { 0x02fac398, 0x02facafd }, 3,
    0xc0c0c0c0, 22556,
    "1a91e3dace36e2be3bf030a65679fe821aa1d6ef92e7c9902eb318182c355691"
};

const kw_chainparams KW_DOGE_TESTNET = {
    "dogecoin-testnet", 0x71, 0xc4, 0xf1,
    { 0x04358394, 0x043587cf }, 1,
    0xdcb7c1fc, 44556,
    "bb0a78264637406b6360aad926284d544d7049f45189db5664f3c4d07350559e"
};

const kw_chainparams KW_DOGE_REGTEST = {
    "dogecoin-regtest", 0x6f, 0xc4, 0xef,
    { 0x04358394, 0x043587cf }, 1,
    0xdab5bffa, 18444,
    "3d2160a3b5dc4a9d62e7e66a295f70313ac808440ef7400d6c0772171ce973a5"
};
