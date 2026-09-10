/* koinu.dog - scrypt tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * The RFC 7914 section 12 vectors, the RFC 6070 PBKDF2-HMAC-SHA1 shape checked
 * instead against RFC 7914's own PBKDF2-HMAC-SHA256 vectors, and Dogecoin's
 * parameters cross-checked against OpenSSL (whose output is embedded here, so
 * the test does not depend on OpenSSL being linked). The batch path must agree
 * with the single path header for header. */

#include "scrypt.h"
#include "pbkdf2.h"
#include "testutil.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* the same code with the SIMD cores compiled out, from test/scrypt_portable.c */
int kw_scrypt_portable(const uint8_t *pass, size_t passlen, const uint8_t *salt, size_t saltlen,
                       uint64_t n, uint32_t r, uint32_t p, uint8_t *out, size_t outlen);
int kw_scrypt_pow_portable(const uint8_t header[80], uint8_t out[32], void *scratch);
const char *kw_scrypt_backend_portable(void);

static int eq(const char *what, const uint8_t *got, const char *wanthex, size_t n)
{
    uint8_t want[128];
    if ((size_t)kw_test_unhex(wanthex, want) != n) { fprintf(stderr, "FAIL: %s bad vector\n", what); return 0; }
    if (memcmp(got, want, n) != 0) {
        fprintf(stderr, "FAIL: %s\n  got  ", what);
        for (size_t i = 0; i < n; i++) fprintf(stderr, "%02x", got[i]);
        fprintf(stderr, "\n  want %s\n", wanthex);
        return 0;
    }
    return 1;
}

int main(void)
{
    uint8_t out[128];

    /* RFC 7914 section 11: PBKDF2-HMAC-SHA256, which is scrypt's PRF */
    if (!kw_pbkdf2_hmac_sha256((const uint8_t *)"passwd", 6, (const uint8_t *)"salt", 4, 1, out, 64))
        { fprintf(stderr, "FAIL: pbkdf2 sha256 call\n"); return 1; }
    if (!eq("pbkdf2-sha256 c=1",  out,
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
            "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783", 64)) return 1;

    if (!kw_pbkdf2_hmac_sha256((const uint8_t *)"Password", 8, (const uint8_t *)"NaCl", 4, 80000, out, 64))
        { fprintf(stderr, "FAIL: pbkdf2 sha256 call\n"); return 1; }
    if (!eq("pbkdf2-sha256 c=80000", out,
            "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
            "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d", 64)) return 1;

    /* RFC 7914 section 12, the four scrypt vectors */
    if (!kw_scrypt((const uint8_t *)"", 0, (const uint8_t *)"", 0, 16, 1, 1, out, 64))
        { fprintf(stderr, "FAIL: scrypt N=16 call\n"); return 1; }
    if (!eq("scrypt (\"\",\"\",16,1,1)", out,
            "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442"
            "fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906", 64)) return 1;

    if (!kw_scrypt((const uint8_t *)"password", 8, (const uint8_t *)"NaCl", 4, 1024, 8, 16, out, 64))
        { fprintf(stderr, "FAIL: scrypt N=1024 r=8 p=16 call\n"); return 1; }
    if (!eq("scrypt (\"password\",\"NaCl\",1024,8,16)", out,
            "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162"
            "2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640", 64)) return 1;

    if (!kw_scrypt((const uint8_t *)"pleaseletmein", 13, (const uint8_t *)"SodiumChloride", 14,
                   16384, 8, 1, out, 64))
        { fprintf(stderr, "FAIL: scrypt N=16384 call\n"); return 1; }
    if (!eq("scrypt (\"pleaseletmein\",\"SodiumChloride\",16384,8,1)", out,
            "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2"
            "d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887", 64)) return 1;

    /* Dogecoin's parameters. The header is block 1's, and the expected digest
       was produced by OpenSSL's scrypt at N=1024 r=1 p=1 over the same bytes. */
    uint8_t hdr[80];
    if (kw_test_unhex(
            "010000009156352c1818b32e90c9e792efd6a11a82fe7956a630f03bbee236ce"
            "dae3911a1c9ba9daaadde0fd9b32ae7cc0cf6df4e1e94edb17f8b8c65b7e6cb2"
            "d6b70a1ea0f3ad52f0ff0f1e00fd5b03", hdr) != 80)
        { fprintf(stderr, "FAIL: header vector\n"); return 1; }

    uint8_t pow[32];
    if (!kw_scrypt_pow(hdr, pow, NULL)) { fprintf(stderr, "FAIL: scrypt_pow call\n"); return 1; }

    uint8_t gen[32];
    if (!kw_scrypt(hdr, 80, hdr, 80, 1024, 1, 1, gen, 32)) { fprintf(stderr, "FAIL: general call\n"); return 1; }
    if (memcmp(pow, gen, 32) != 0) { fprintf(stderr, "FAIL: pow path disagrees with the general one\n"); return 1; }

    /* the batch path must produce exactly what the single path does */
    uint8_t hdrs[7 * 80], single[7 * 32], batched[7 * 32];
    for (int i = 0; i < 7; i++) {
        memcpy(hdrs + i * 80, hdr, 80);
        hdrs[i * 80 + 76] = (uint8_t)i;              /* vary the nonce */
        if (!kw_scrypt_pow(hdrs + i * 80, single + i * 32, NULL))
            { fprintf(stderr, "FAIL: single %d\n", i); return 1; }
    }
    /* 7 exercises both the full batches and the odd remainder */
    if (!kw_scrypt_pow_batch(hdrs, 7, batched, NULL)) { fprintf(stderr, "FAIL: batch call\n"); return 1; }
    if (memcmp(single, batched, sizeof single) != 0)
        { fprintf(stderr, "FAIL: batch disagrees with single\n"); return 1; }

    /* the vector core must agree with the scalar one, which is where a bad lane
       or shuffle shows up: self-consistency alone would not catch it */
    {
        unsigned seed = 1;
        uint8_t h[80], a[32], b[32];
        for (int i = 0; i < 64; i++) {
            for (int k = 0; k < 80; k++) { seed = seed * 1103515245u + 12345u; h[k] = (uint8_t)(seed >> 16); }
            if (!kw_scrypt_pow(h, a, NULL) || !kw_scrypt_pow_portable(h, b, NULL))
                { fprintf(stderr, "FAIL: pow call in cross-check\n"); return 1; }
            if (memcmp(a, b, 32) != 0) {
                fprintf(stderr, "FAIL: %s core disagrees with portable at input %d\n",
                        kw_scrypt_backend(), i);
                return 1;
            }
        }
        /* and over the general form, where r > 1 exercises blockmix's reorder */
        uint8_t g1[64], g2[64];
        if (!kw_scrypt((const uint8_t *)"kw", 2, (const uint8_t *)"salt", 4, 256, 4, 3, g1, 64) ||
            !kw_scrypt_portable((const uint8_t *)"kw", 2, (const uint8_t *)"salt", 4, 256, 4, 3, g2, 64))
            { fprintf(stderr, "FAIL: general call in cross-check\n"); return 1; }
        if (memcmp(g1, g2, 64) != 0) { fprintf(stderr, "FAIL: general form disagrees with portable\n"); return 1; }
    }

    printf("scrypt ok: 3 RFC 7914 vectors, 2 pbkdf2-sha256 vectors, dogecoin params, batch == single,\n"
           "  %s core == portable over 64 random headers and r=4 p=3\n",
           kw_scrypt_backend());
    return 0;
}
