/* koinu.dog - HMAC known-answer tests (RFC 4231)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "hmac.h"
#include "testutil.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    uint8_t o[64];

    /* Case 1: 20-byte 0x0b key, "Hi There" */
    {
        uint8_t k[20]; memset(k, 0x0b, sizeof k);
        const char *m = "Hi There";
        kw_hmac_sha256(k, sizeof k, (const uint8_t *)m, strlen(m), o);
        kw_test_check("hmac256 case1", o, 32,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        kw_hmac_sha512(k, sizeof k, (const uint8_t *)m, strlen(m), o);
        kw_test_check("hmac512 case1", o, 64,
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
            "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
    }

    /* Case 2: key "Jefe", "what do ya want for nothing?" */
    {
        const char *k = "Jefe";
        const char *m = "what do ya want for nothing?";
        kw_hmac_sha256((const uint8_t *)k, strlen(k), (const uint8_t *)m, strlen(m), o);
        kw_test_check("hmac256 case2", o, 32,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        kw_hmac_sha512((const uint8_t *)k, strlen(k), (const uint8_t *)m, strlen(m), o);
        kw_test_check("hmac512 case2", o, 64,
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
            "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737");
    }

    /* Case 3: 20-byte 0xaa key, 50-byte 0xdd data */
    {
        uint8_t k[20]; memset(k, 0xaa, sizeof k);
        uint8_t m[50]; memset(m, 0xdd, sizeof m);
        kw_hmac_sha256(k, sizeof k, m, sizeof m, o);
        kw_test_check("hmac256 case3", o, 32,
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
        kw_hmac_sha512(k, sizeof k, m, sizeof m, o);
        kw_test_check("hmac512 case3", o, 64,
            "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39"
            "bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb");
    }

    /* Case 6: 131-byte 0xaa key (hashed first), long message */
    {
        uint8_t k[131]; memset(k, 0xaa, sizeof k);
        const char *m = "Test Using Larger Than Block-Size Key - Hash Key First";
        kw_hmac_sha256(k, sizeof k, (const uint8_t *)m, strlen(m), o);
        kw_test_check("hmac256 case6", o, 32,
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
        kw_hmac_sha512(k, sizeof k, (const uint8_t *)m, strlen(m), o);
        kw_test_check("hmac512 case6", o, 64,
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352"
            "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598");
    }

    if (kw_test_fails()) { fprintf(stderr, "%d hmac vector(s) failed\n", kw_test_fails()); return 1; }
    printf("hmac ok: rfc 4231 cases 1,2,3,6 for sha256 and sha512\n");
    return 0;
}
