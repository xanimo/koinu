/* koinu.dog - proof of work arithmetic
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * 256-bit integers as eight 32-bit limbs, least significant first, with only the
 * operations the two PoW rules need: compare, add, subtract, shift, and one
 * division. The division runs once per header at most, so it is the obvious
 * shift-and-subtract rather than anything clever.
 *
 * Checked in test/test_pow.c against Bitcoin's own SetCompact vectors, against
 * Dogecoin's block 1 hashed with scrypt, and against work values computed
 * independently. */

#include "pow.h"

#include <string.h>

void kw_u256_zero(kw_u256 *a) { memset(a, 0, sizeof *a); }

int kw_u256_is_zero(const kw_u256 *a)
{
    for (int i = 0; i < 8; i++) if (a->w[i]) return 0;
    return 1;
}

void kw_u256_from_bytes(const uint8_t b[32], kw_u256 *out)
{
    for (int i = 0; i < 8; i++)
        out->w[i] = (uint32_t)b[i * 4] | ((uint32_t)b[i * 4 + 1] << 8) |
                    ((uint32_t)b[i * 4 + 2] << 16) | ((uint32_t)b[i * 4 + 3] << 24);
}

void kw_u256_to_bytes(const kw_u256 *a, uint8_t b[32])
{
    for (int i = 0; i < 8; i++) {
        b[i * 4]     = (uint8_t)a->w[i];
        b[i * 4 + 1] = (uint8_t)(a->w[i] >> 8);
        b[i * 4 + 2] = (uint8_t)(a->w[i] >> 16);
        b[i * 4 + 3] = (uint8_t)(a->w[i] >> 24);
    }
}

int kw_u256_cmp(const kw_u256 *a, const kw_u256 *b)
{
    for (int i = 7; i >= 0; i--) {
        if (a->w[i] < b->w[i]) return -1;
        if (a->w[i] > b->w[i]) return 1;
    }
    return 0;
}

int kw_u256_add(kw_u256 *acc, const kw_u256 *x)
{
    uint64_t carry = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t s = (uint64_t)acc->w[i] + x->w[i] + carry;
        acc->w[i] = (uint32_t)s;
        carry = s >> 32;
    }
    return (int)carry;
}

static void sub(kw_u256 *a, const kw_u256 *b)
{
    uint64_t borrow = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t d = (uint64_t)a->w[i] - b->w[i] - borrow;
        a->w[i] = (uint32_t)d;
        borrow = (d >> 32) & 1;
    }
}

static void shl1(kw_u256 *a)
{
    uint32_t carry = 0;
    for (int i = 0; i < 8; i++) {
        uint32_t next = a->w[i] >> 31;
        a->w[i] = (a->w[i] << 1) | carry;
        carry = next;
    }
}

static int bit(const kw_u256 *a, int i) { return (a->w[i / 32] >> (i % 32)) & 1; }

static void set_bit(kw_u256 *a, int i) { a->w[i / 32] |= 1u << (i % 32); }

/* a * m, 0 on overflow, and a / d. Both divisors and multipliers here are small
   enough that a limb at a time is exact in 64 bits. */
static int mul_small(kw_u256 *a, uint64_t m)
{
    uint64_t carry = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t p = (uint64_t)a->w[i] * m + carry;
        a->w[i] = (uint32_t)p;
        carry = p >> 32;
    }
    return carry == 0;
}

static void div_small(kw_u256 *a, uint64_t d)
{
    uint64_t rem = 0;
    if (!d) return;
    for (int i = 7; i >= 0; i--) {
        uint64_t cur = (rem << 32) | a->w[i];
        a->w[i] = (uint32_t)(cur / d);
        rem = cur % d;
    }
}

/* q = num / den, den nonzero. No remainder is wanted anywhere here. */
static void divide(const kw_u256 *num, const kw_u256 *den, kw_u256 *q)
{
    kw_u256 r;
    kw_u256_zero(&r);
    kw_u256_zero(q);
    for (int i = 255; i >= 0; i--) {
        shl1(&r);
        r.w[0] |= (uint32_t)bit(num, i);
        if (kw_u256_cmp(&r, den) >= 0) { sub(&r, den); set_bit(q, i); }
    }
}

/* nBits is an exponent byte and a 24-bit mantissa: target = mantissa *
   256^(exponent-3), with bit 0x00800000 of the mantissa meaning negative, which
   a target never is. */
int kw_bits_target(uint32_t bits, kw_u256 *out)
{
    uint32_t mant = bits & 0x007fffffu;
    uint32_t expo = bits >> 24;

    if (bits & 0x00800000u) return 0;                 /* negative */
    kw_u256_zero(out);
    if (mant == 0) return 0;                          /* zero is never a target */

    if (expo <= 3) {
        out->w[0] = mant >> (8 * (3 - expo));
        return !kw_u256_is_zero(out);                 /* shifted away to nothing */
    }
    /* the whole mantissa has to land under bit 256, which is not the same as
       bounding the exponent: 0x22001234 has a small exponent for its mantissa
       and still runs off the top */
    unsigned shift = 8 * (expo - 3), mbits = 0;
    for (uint32_t m = mant; m; m >>= 1) mbits++;
    if (shift + mbits > 256) return 0;

    unsigned limb = shift / 32, off = shift % 32;
    out->w[limb] = mant << off;
    /* The part that crosses into the next limb is zero when the mantissa ends in
       the top one, by the bound above. Writing it anyway is a store past the end
       that happens to store zero, which is invisible without a sanitizer. */
    if (off && limb + 1 < 8) out->w[limb + 1] = mant >> (32 - off);
    return 1;
}

uint32_t kw_target_bits(const kw_u256 *t)
{
    int high = -1;
    for (int i = 255; i >= 0; i--) if (bit(t, i)) { high = i; break; }
    if (high < 0) return 0;

    unsigned bytes = (unsigned)high / 8 + 1;          /* significant bytes */
    /* the mantissa is the top three bytes, and must stay positive */
    kw_u256 tmp = *t;
    unsigned drop = bytes > 3 ? (bytes - 3) * 8 : 0;
    for (unsigned i = 0; i < drop; i++) {
        for (int k = 0; k < 8; k++)
            tmp.w[k] = (tmp.w[k] >> 1) | (k < 7 ? tmp.w[k + 1] << 31 : 0);
    }
    uint32_t mant = tmp.w[0];
    if (bytes < 3) mant <<= 8 * (3 - bytes);
    uint32_t expo = bytes;
    if (mant & 0x00800000u) { mant >>= 8; expo++; }
    return (expo << 24) | (mant & 0x007fffffu);
}

int kw_bits_work(uint32_t bits, kw_u256 *out)
{
    kw_u256 target;
    if (!kw_bits_target(bits, &target)) return 0;

    /* 2^256/(t+1) without a 257th bit: (~t)/(t+1) + 1, since 2^256 = (~t) + (t+1) */
    kw_u256 denom = target, num, one;
    kw_u256_zero(&one);
    one.w[0] = 1;
    if (kw_u256_add(&denom, &one)) {                  /* t was 2^256-1 */
        kw_u256_zero(out);
        out->w[0] = 1;
        return 1;
    }
    for (int i = 0; i < 8; i++) num.w[i] = ~target.w[i];
    divide(&num, &denom, out);
    kw_u256_add(out, &one);
    return 1;
}

int kw_pow_check(const uint8_t pow_hash[32], uint32_t bits)
{
    kw_u256 target, h;
    if (!kw_bits_target(bits, &target)) return 0;
    kw_u256_from_bytes(pow_hash, &h);
    return kw_u256_cmp(&h, &target) <= 0;
}

uint32_t kw_header_bits(const uint8_t header[80])
{
    return (uint32_t)header[72] | ((uint32_t)header[73] << 8) |
           ((uint32_t)header[74] << 16) | ((uint32_t)header[75] << 24);
}

uint32_t kw_header_time(const uint8_t header[80])
{
    return (uint32_t)header[68] | ((uint32_t)header[69] << 8) |
           ((uint32_t)header[70] << 16) | ((uint32_t)header[71] << 24);
}

/* ── the retarget rule ───────────────────────────────────────────────────
   Dogecoin's, from src/pow.cpp and src/dogecoin.cpp: a 240-block period at four
   hours before 145000, then DigiShield's one-block period at one minute. */

const kw_pow_rules KW_POW_MAIN = {
    145000,             /* the first height the per-block period applies to */
    0x1e0fffffu,        /* ~uint256(0) >> 20, compact */
    4 * 60 * 60,        /* pre-digishield: four hours a period */
    60,                 /* post: one minute */
    60                  /* a block a minute either way */
};

/* The two conditions differ by one block, which is the whole subtlety. The period
   length comes from the previous block's height, so height 145000 still belongs to
   a 240-block period, and 145000 % 240 is 40, so it retargets nothing and carries
   144999's nBits. The damping and the timespan come from the height being
   validated, so 145000 would have used them had it retargeted. 145001 is the first
   height that actually recomputes every block. */
static int per_block(const kw_pow_rules *r, uint32_t height)
{
    return height >= 1 && (height - 1) >= r->digishield_height;
}

static int digishield(const kw_pow_rules *r, uint32_t height)
{
    return height >= r->digishield_height;
}

int kw_pow_retargets(const kw_pow_rules *r, uint32_t height, uint32_t *first_height)
{
    if (!r || !first_height || height == 0) return 0;   /* genesis carries its own */

    uint32_t interval = per_block(r, height)
                        ? 1u : (uint32_t)(r->timespan_pre / r->spacing);
    if (interval == 0) return 0;
    if (height % interval != 0) return 0;

    /* Go back a whole period, except for the first retarget after genesis, which
       goes back one less. Litecoin's fix for a difficulty attack, inherited. */
    uint32_t back = (height == interval) ? interval - 1 : interval;
    if (back > height - 1) return 0;
    *first_height = (height - 1) - back;
    return 1;
}

uint32_t kw_pow_next_bits(const kw_pow_rules *r, uint32_t height, uint32_t last_bits,
                          uint32_t last_time, uint32_t first_time)
{
    uint32_t first_height;
    if (!r || !kw_pow_retargets(r, height, &first_height)) return last_bits;

    int64_t span = digishield(r, height) ? r->timespan_post : r->timespan_pre;
    int64_t actual = (int64_t)last_time - (int64_t)first_time;
    int64_t lo, hi;

    if (digishield(r, height)) {
        actual = span + (actual - span) / 8;        /* the amplitude filter */
        lo = span - span / 4;
        hi = span + span / 2;
    } else if (height > 10000) {
        lo = span / 4;  hi = span * 4;
    } else if (height > 5000) {
        lo = span / 8;  hi = span * 4;
    } else {
        lo = span / 16; hi = span * 4;
    }
    if (actual < lo) actual = lo;
    else if (actual > hi) actual = hi;

    kw_u256 target, limit;
    if (!kw_bits_target(last_bits, &target)) return last_bits;
    if (!kw_bits_target(r->powlimit_bits, &limit)) return last_bits;

    /* actual is at most four times a four-hour period, so this cannot overflow a
       target that is already at or below the limit. It is checked rather than
       assumed: an overflow would wrap to a small number, which reads as a
       harder target than the chain asked for. */
    if (!mul_small(&target, (uint64_t)actual)) return r->powlimit_bits;
    div_small(&target, (uint64_t)span);

    if (kw_u256_cmp(&target, &limit) > 0) return r->powlimit_bits;
    return kw_target_bits(&target);
}
