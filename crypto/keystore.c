/* koinu.dog - encrypted keystore
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "keystore.h"
#include "kdf.h"
#include "aead.h"
#include "rng.h"
#include "mem.h"

#include <string.h>

const kw_keystore_params KW_KEYSTORE_DEFAULT = { 3, 65536, 1 };

/* on-disk layout, all little-endian:
     0  magic "DWKS"
     4  version(1) kdf(1) aead(1) reserved(1)
     8  argon2 t_cost(4), m_cost_kib(4), parallelism(4)
    20  salt(16)
    36  nonce(12)
    48  ct_len(4)
    -- the 52 bytes above are the authenticated header --
    52  ciphertext(ct_len)
    52+ct_len  tag(16) */
#define KS_MAGIC0 'D'
#define KS_MAGIC1 'W'
#define KS_MAGIC2 'K'
#define KS_MAGIC3 'S'
#define KS_VERSION 1
#define KS_KDF_ARGON2ID 1
#define KS_AEAD_CHACHA20POLY1305 1
#define KS_SALT 16
#define KS_NONCE KW_AEAD_NONCE
#define KS_HDR 52
#define KS_TAG KW_AEAD_TAG

static void put_le32(uint8_t *o, uint32_t v)
{
    o[0]=(uint8_t)v; o[1]=(uint8_t)(v>>8); o[2]=(uint8_t)(v>>16); o[3]=(uint8_t)(v>>24);
}
static uint32_t get_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}

size_t kw_keystore_sealed_size(size_t secretlen)
{
    return KS_HDR + secretlen + KS_TAG;
}

size_t kw_keystore_seal(const uint8_t *secret, size_t secretlen,
                        const char *passphrase,
                        const kw_keystore_params *params,
                        uint8_t *out, size_t outcap)
{
    if (!secret || !passphrase || !params) return 0;
    if (secretlen == 0 || secretlen > KW_KEYSTORE_MAX_SECRET) return 0;
    size_t total = kw_keystore_sealed_size(secretlen);
    if (total > outcap) return 0;

    uint8_t salt[KS_SALT], nonce[KS_NONCE];
    if (!kw_random_bytes(salt, sizeof salt))  return 0;
    if (!kw_random_bytes(nonce, sizeof nonce)) return 0;

    out[0]=KS_MAGIC0; out[1]=KS_MAGIC1; out[2]=KS_MAGIC2; out[3]=KS_MAGIC3;
    out[4]=KS_VERSION; out[5]=KS_KDF_ARGON2ID; out[6]=KS_AEAD_CHACHA20POLY1305; out[7]=0;
    put_le32(out + 8,  params->t_cost);
    put_le32(out + 12, params->m_cost_kib);
    put_le32(out + 16, params->parallelism);
    memcpy(out + 20, salt, KS_SALT);
    memcpy(out + 36, nonce, KS_NONCE);
    put_le32(out + 48, (uint32_t)secretlen);

    uint8_t key[KW_AEAD_KEY];
    if (!kw_argon2id((const uint8_t *)passphrase, strlen(passphrase),
                     salt, sizeof salt, params->t_cost, params->m_cost_kib,
                     params->parallelism, key, sizeof key)) {
        kw_secure_zero(salt, sizeof salt); kw_secure_zero(nonce, sizeof nonce);
        return 0;
    }

    /* header is the AAD, so version and kdf params are tamper-evident */
    kw_chacha20poly1305_encrypt(key, nonce, out, KS_HDR, secret, secretlen,
                                out + KS_HDR, out + KS_HDR + secretlen);

    kw_secure_zero(key, sizeof key);
    kw_secure_zero(salt, sizeof salt);
    kw_secure_zero(nonce, sizeof nonce);
    return total;
}

int kw_keystore_open(const uint8_t *blob, size_t bloblen,
                     const char *passphrase,
                     uint8_t *out, size_t outcap, size_t *secretlen)
{
    if (!blob || !passphrase || bloblen < KS_HDR + KS_TAG) return 0;
    if (blob[0]!=KS_MAGIC0 || blob[1]!=KS_MAGIC1 || blob[2]!=KS_MAGIC2 || blob[3]!=KS_MAGIC3)
        return 0;
    if (blob[4]!=KS_VERSION || blob[5]!=KS_KDF_ARGON2ID || blob[6]!=KS_AEAD_CHACHA20POLY1305)
        return 0;

    uint32_t t = get_le32(blob + 8), m = get_le32(blob + 12), p = get_le32(blob + 16);
    if (t == 0 || m == 0 || p == 0) return 0;
    /* before the KDF runs, since the tag is only checkable after it */
    if (t > KW_KEYSTORE_MAX_T_COST || m > KW_KEYSTORE_MAX_M_COST_KIB ||
        p > KW_KEYSTORE_MAX_PARALLELISM) return 0;
    const uint8_t *salt = blob + 20;
    const uint8_t *nonce = blob + 36;
    uint32_t ctlen = get_le32(blob + 48);
    if (ctlen == 0 || ctlen > KW_KEYSTORE_MAX_SECRET) return 0;
    if (bloblen != (size_t)KS_HDR + ctlen + KS_TAG) return 0;
    if (ctlen > outcap) return 0;

    uint8_t key[KW_AEAD_KEY];
    if (!kw_argon2id((const uint8_t *)passphrase, strlen(passphrase),
                     salt, KS_SALT, t, m, p, key, sizeof key))
        return 0;

    int ok = kw_chacha20poly1305_decrypt(key, nonce, blob, KS_HDR,
                                         blob + KS_HDR, ctlen,
                                         blob + KS_HDR + ctlen, out);
    kw_secure_zero(key, sizeof key);
    if (!ok) return 0;
    if (secretlen) *secretlen = ctlen;
    return 1;
}
