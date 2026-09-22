/* koinu.dog - BIP32 hierarchical deterministic keys
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "bip32.h"
#include "hmac.h"
#include "ec.h"
#include "ripemd160.h"
#include "base58.h"
#include "mem.h"

#include <string.h>

static void be32(uint8_t *o, uint32_t v)
{
    o[0] = (uint8_t)(v >> 24); o[1] = (uint8_t)(v >> 16);
    o[2] = (uint8_t)(v >> 8);  o[3] = (uint8_t)v;
}
static uint32_t rd_be32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

int kw_bip32_pubkey(const kw_bip32_key *k, uint8_t pub[33])
{
    if (k->is_private) return kw_ec_pubkey(k->key + 1, pub);
    memcpy(pub, k->key, 33);
    return 1;
}

static int fingerprint(const kw_bip32_key *k, uint8_t fp[4])
{
    uint8_t pub[33], h[KW_RIPEMD160_LEN];
    if (!kw_bip32_pubkey(k, pub)) return 0;
    kw_hash160(pub, 33, h);
    memcpy(fp, h, 4);
    return 1;
}

int kw_bip32_from_seed(const uint8_t *seed, size_t seedlen,
                       kw_bip32_version ver, kw_bip32_key *out)
{
    uint8_t I[64];
    kw_hmac_sha512((const uint8_t *)"Bitcoin seed", 12, seed, seedlen, I);
    if (!kw_ec_seckey_verify(I)) { kw_secure_zero(I, sizeof I); return 0; }

    memset(out, 0, sizeof *out);
    out->is_private = 1;
    out->depth = 0;
    out->child_number = 0;
    out->key[0] = 0x00;
    memcpy(out->key + 1, I, 32);
    memcpy(out->chain_code, I + 32, 32);
    out->ver = ver;
    kw_secure_zero(I, sizeof I);
    return 1;
}

int kw_bip32_ckd_priv(const kw_bip32_key *parent, uint32_t index, kw_bip32_key *out)
{
    if (!parent->is_private) return 0;

    uint8_t data[37], I[64];
    if (index >= KW_BIP32_HARDENED) {
        data[0] = 0x00;
        memcpy(data + 1, parent->key + 1, 32);      /* the secret */
    } else if (!kw_bip32_pubkey(parent, data)) {    /* compressed pub */
        kw_secure_zero(data, sizeof data);
        return 0;
    }
    be32(data + 33, index);
    kw_hmac_sha512(parent->chain_code, 32, data, sizeof data, I);

    kw_bip32_key c;
    memset(&c, 0, sizeof c);
    c.is_private = 1;
    c.key[0] = 0x00;
    memcpy(c.key + 1, parent->key + 1, 32);
    if (!kw_ec_seckey_tweak_add(c.key + 1, I)) {     /* ki = (IL + kpar) mod n */
        /* BIP32: IL >= n or ki == 0 means proceed with the next index, not fail.
           Around 2^-127, so this has never run, but a wallet that returned an
           error here would lose the whole branch below it. The last index of a
           run has no next one. */
        kw_secure_zero(I, sizeof I); kw_secure_zero(data, sizeof data);
        kw_secure_zero(&c, sizeof c);
        if (index == UINT32_MAX || index == KW_BIP32_HARDENED - 1) return 0;
        return kw_bip32_ckd_priv(parent, index + 1, out);
    }
    memcpy(c.chain_code, I + 32, 32);
    c.depth = parent->depth + 1;
    c.child_number = index;
    if (!fingerprint(parent, c.parent_fp)) {
        kw_secure_zero(I, sizeof I); kw_secure_zero(data, sizeof data);
        kw_secure_zero(&c, sizeof c);
        return 0;
    }
    c.ver = parent->ver;

    *out = c;
    kw_secure_zero(I, sizeof I);
    kw_secure_zero(data, sizeof data);
    kw_secure_zero(&c, sizeof c);
    return 1;
}

int kw_bip32_ckd_pub(const kw_bip32_key *parent, uint32_t index, kw_bip32_key *out)
{
    if (index >= KW_BIP32_HARDENED) return 0;         /* impossible without the secret */

    uint8_t data[37], I[64];
    if (!kw_bip32_pubkey(parent, data)) return 0;
    be32(data + 33, index);
    kw_hmac_sha512(parent->chain_code, 32, data, sizeof data, I);

    kw_bip32_key c;
    memset(&c, 0, sizeof c);
    c.is_private = 0;
    if (!kw_bip32_pubkey(parent, c.key)) { kw_secure_zero(I, sizeof I); return 0; }
    if (!kw_ec_pubkey_tweak_add(c.key, I)) {          /* Ki = IL*G + Kpar */
        kw_secure_zero(I, sizeof I);
        return 0;
    }
    memcpy(c.chain_code, I + 32, 32);
    c.depth = parent->depth + 1;
    c.child_number = index;
    if (!fingerprint(parent, c.parent_fp)) { kw_secure_zero(I, sizeof I); return 0; }
    c.ver = parent->ver;

    *out = c;
    kw_secure_zero(I, sizeof I);
    return 1;
}

int kw_bip32_neuter(const kw_bip32_key *prv, kw_bip32_key *pub)
{
    kw_bip32_key p;
    memset(&p, 0, sizeof p);
    p.is_private = 0;
    p.depth = prv->depth;
    memcpy(p.parent_fp, prv->parent_fp, 4);
    p.child_number = prv->child_number;
    memcpy(p.chain_code, prv->chain_code, 32);
    if (!kw_bip32_pubkey(prv, p.key)) return 0;
    p.ver = prv->ver;
    *pub = p;
    return 1;
}

size_t kw_bip32_serialize(const kw_bip32_key *k, char *out, size_t outcap)
{
    uint8_t buf[KW_BIP32_SERIALIZED_LEN];
    be32(buf, k->is_private ? k->ver.prv : k->ver.pub);
    buf[4] = k->depth;
    memcpy(buf + 5, k->parent_fp, 4);
    be32(buf + 9, k->child_number);
    memcpy(buf + 13, k->chain_code, 32);
    memcpy(buf + 45, k->key, 33);
    size_t n = kw_base58check_encode(buf, sizeof buf, out, outcap);
    kw_secure_zero(buf, sizeof buf);
    return n;
}

int kw_bip32_parse(const char *str, kw_bip32_key *out)
{
    uint8_t buf[KW_BIP32_SERIALIZED_LEN + 8];
    size_t n = 0;
    if (!kw_base58check_decode(str, buf, sizeof buf, &n)) return 0;
    if (n != KW_BIP32_SERIALIZED_LEN) return 0;

    kw_bip32_key k;
    memset(&k, 0, sizeof k);
    uint32_t ver = rd_be32(buf);
    k.depth = buf[4];
    memcpy(k.parent_fp, buf + 5, 4);
    k.child_number = rd_be32(buf + 9);
    memcpy(k.chain_code, buf + 13, 32);
    memcpy(k.key, buf + 45, 33);

    if (k.key[0] == 0x00) { k.is_private = 1; k.ver.prv = ver; }
    else if (k.key[0] == 0x02 || k.key[0] == 0x03) { k.is_private = 0; k.ver.pub = ver; }
    else { kw_secure_zero(buf, sizeof buf); kw_secure_zero(&k, sizeof k); return 0; }

    *out = k;
    kw_secure_zero(buf, sizeof buf);
    kw_secure_zero(&k, sizeof k);
    return 1;
}

int kw_bip32_derive_path(const kw_bip32_key *master, const char *path, kw_bip32_key *out)
{
    const char *p = path;
    if (*p == 'm' || *p == 'M') p++;
    if (*p == '/') p++;
    else if (*p != '\0') return 0;     /* must start with m, m/, or empty */

    kw_bip32_key cur = *master;
    while (*p) {
        uint32_t index = 0;
        int digits = 0;
        while (*p >= '0' && *p <= '9') {
            index = index * 10 + (uint32_t)(*p - '0');
            if (index >= KW_BIP32_HARDENED) return 0;   /* number too large */
            p++; digits++;
        }
        if (!digits) return 0;
        if (*p == '\'' || *p == 'h' || *p == 'H') { index += KW_BIP32_HARDENED; p++; }

        kw_bip32_key next;
        int ok = cur.is_private ? kw_bip32_ckd_priv(&cur, index, &next)
                                : kw_bip32_ckd_pub(&cur, index, &next);
        if (!ok) { kw_secure_zero(&cur, sizeof cur); return 0; }
        kw_secure_zero(&cur, sizeof cur);
        cur = next;
        kw_secure_zero(&next, sizeof next);

        if (*p == '/') p++;
        else if (*p != '\0') return 0;
    }

    *out = cur;
    kw_secure_zero(&cur, sizeof cur);
    return 1;
}
