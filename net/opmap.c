/* koinu.dog - outpoint to scriptPubKey, for generating filters
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "opmap.h"
#include "sha2.h"

#include <stdlib.h>
#include <string.h>

/* Open addressing with linear probing. A spend removes an entry, so deletions
   are as frequent as insertions and tombstones would come to outnumber the
   data: this shifts the probe chain back instead, which keeps the table clean
   under any mix of the two. */

#define SLOT_EMPTY  0
#define SLOT_INLINE 1
#define SLOT_HEAP   2

struct slot {
    uint8_t  key[16];
    uint8_t  type;
    uint8_t  len;                         /* inline length */
    uint8_t  spk[KW_OPMAP_INLINE];
    uint32_t ext;                         /* heap: index into the long list */
};

struct longspk { uint8_t *p; uint16_t len; };

struct kw_opmap {
    struct slot *tab;
    size_t cap;                           /* a power of two */
    size_t count;

    struct longspk *lng;                  /* scripts past KW_OPMAP_INLINE */
    size_t nlng, caplng;
    uint32_t *freelng;                    /* indices returned by a take */
    size_t nfree, capfree;
};

/* The outpoint digested to 16 bytes. 128 bits over any set this will ever hold
   makes a collision less likely than the machine being wrong, and a collision
   here would hand a spend the wrong script, which is a filter that hides a
   payment. The outpoint itself is 36 bytes and keeping it would cost more than
   twice as much per entry. */
static void opkey(const uint8_t op[KW_OPMAP_OUTPOINT], uint8_t out[16])
{
    uint8_t h[32];
    kw_sha256(op, KW_OPMAP_OUTPOINT, h);
    memcpy(out, h, 16);
}

static size_t ideal(const uint8_t key[16], size_t cap)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)key[i] << (8 * i);
    return (size_t)(v & (uint64_t)(cap - 1));
}

kw_opmap *kw_opmap_new(void)
{
    kw_opmap *m = (kw_opmap *)calloc(1, sizeof *m);
    if (!m) return NULL;
    m->cap = 1024;
    m->tab = (struct slot *)calloc(m->cap, sizeof *m->tab);
    if (!m->tab) { free(m); return NULL; }
    return m;
}

void kw_opmap_free(kw_opmap *m)
{
    if (!m) return;
    for (size_t i = 0; i < m->nlng; i++) free(m->lng[i].p);
    free(m->lng);
    free(m->freelng);
    free(m->tab);
    free(m);
}

size_t kw_opmap_count(const kw_opmap *m) { return m ? m->count : 0; }
size_t kw_opmap_capacity(const kw_opmap *m) { return m ? m->cap : 0; }

/* Place without growing or touching the long list: used by insert and by the
   rehash, which moves slots that already own their storage. */
static void place(struct slot *tab, size_t cap, const struct slot *s)
{
    size_t i = ideal(s->key, cap);
    while (tab[i].type != SLOT_EMPTY) {
        if (memcmp(tab[i].key, s->key, 16) == 0) break;   /* replace */
        i = (i + 1) & (cap - 1);
    }
    tab[i] = *s;
}

static int grow(kw_opmap *m)
{
    size_t nc = m->cap * 2;
    struct slot *nt = (struct slot *)calloc(nc, sizeof *nt);
    if (!nt) return 0;
    for (size_t i = 0; i < m->cap; i++)
        if (m->tab[i].type != SLOT_EMPTY) place(nt, nc, &m->tab[i]);
    free(m->tab);
    m->tab = nt;
    m->cap = nc;
    return 1;
}

static int long_alloc(kw_opmap *m, const uint8_t *spk, size_t spklen, uint32_t *out)
{
    uint8_t *copy = (uint8_t *)malloc(spklen);
    if (!copy) return 0;
    memcpy(copy, spk, spklen);

    if (m->nfree) {                        /* reuse a slot a take released */
        uint32_t idx = m->freelng[--m->nfree];
        m->lng[idx].p = copy;
        m->lng[idx].len = (uint16_t)spklen;
        *out = idx;
        return 1;
    }
    if (m->nlng == m->caplng) {
        size_t nc = m->caplng ? m->caplng * 2 : 16;
        struct longspk *nl = (struct longspk *)realloc(m->lng, nc * sizeof *nl);
        if (!nl) { free(copy); return 0; }
        m->lng = nl;
        m->caplng = nc;
    }
    m->lng[m->nlng].p = copy;
    m->lng[m->nlng].len = (uint16_t)spklen;
    *out = (uint32_t)m->nlng++;
    return 1;
}

static void long_release(kw_opmap *m, uint32_t idx)
{
    free(m->lng[idx].p);
    m->lng[idx].p = NULL;
    m->lng[idx].len = 0;
    if (m->nfree == m->capfree) {
        size_t nc = m->capfree ? m->capfree * 2 : 16;
        uint32_t *nf = (uint32_t *)realloc(m->freelng, nc * sizeof *nf);
        if (!nf) return;                   /* the index leaks, the bytes do not */
        m->freelng = nf;
        m->capfree = nc;
    }
    m->freelng[m->nfree++] = idx;
}

int kw_opmap_put(kw_opmap *m, const uint8_t op[KW_OPMAP_OUTPOINT],
                 const uint8_t *spk, size_t spklen)
{
    struct slot s;
    if (!m || !op || (spklen && !spk) || spklen > 0xffff) return 0;

    /* Three quarters full: past that, linear probing's chains lengthen fast. */
    if ((m->count + 1) * 4 > m->cap * 3 && !grow(m)) return 0;

    memset(&s, 0, sizeof s);
    opkey(op, s.key);
    if (spklen <= KW_OPMAP_INLINE) {
        s.type = SLOT_INLINE;
        s.len = (uint8_t)spklen;
        if (spklen) memcpy(s.spk, spk, spklen);
    } else {
        uint32_t idx;
        if (!long_alloc(m, spk, spklen, &idx)) return 0;
        s.type = SLOT_HEAP;
        s.ext = idx;
    }

    /* Replacing an existing key has to release what it held, or the long list
       grows without bound on a chain that reuses an outpoint. */
    size_t i = ideal(s.key, m->cap);
    while (m->tab[i].type != SLOT_EMPTY) {
        if (memcmp(m->tab[i].key, s.key, 16) == 0) {
            if (m->tab[i].type == SLOT_HEAP) long_release(m, m->tab[i].ext);
            m->tab[i] = s;
            return 1;
        }
        i = (i + 1) & (m->cap - 1);
    }
    m->tab[i] = s;
    m->count++;
    return 1;
}

int kw_opmap_take(kw_opmap *m, const uint8_t op[KW_OPMAP_OUTPOINT],
                  uint8_t *spk, size_t cap, size_t *len)
{
    uint8_t key[16];
    if (!m || !op) return 0;
    opkey(op, key);

    size_t i = ideal(key, m->cap);
    while (m->tab[i].type != SLOT_EMPTY) {
        if (memcmp(m->tab[i].key, key, 16) == 0) break;
        i = (i + 1) & (m->cap - 1);
    }
    if (m->tab[i].type == SLOT_EMPTY) return 0;

    if (m->tab[i].type == SLOT_INLINE) {
        if (len) *len = m->tab[i].len;
        if (spk && cap >= m->tab[i].len) memcpy(spk, m->tab[i].spk, m->tab[i].len);
    } else {
        struct longspk *l = &m->lng[m->tab[i].ext];
        if (len) *len = l->len;
        if (spk && cap >= l->len) memcpy(spk, l->p, l->len);
        long_release(m, m->tab[i].ext);
    }

    /* Backward shift: walk forward and pull back anything whose ideal slot is
       at or before the hole, so no probe chain is broken by the gap. */
    size_t hole = i, j = i;
    for (;;) {
        j = (j + 1) & (m->cap - 1);
        if (m->tab[j].type == SLOT_EMPTY) break;
        size_t k = ideal(m->tab[j].key, m->cap);
        int movable = (j > hole) ? (k <= hole || k > j) : (k <= hole && k > j);
        if (movable) {
            m->tab[hole] = m->tab[j];
            hole = j;
        }
    }
    memset(&m->tab[hole], 0, sizeof m->tab[hole]);
    m->count--;
    return 1;
}
