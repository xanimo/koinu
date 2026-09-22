/* koinu.dog - p2p message bodies (handshake)
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "msg.h"

#include <string.h>

/* ── bounded writer ──────────────────────────────────────────── */
typedef struct { uint8_t *p; size_t cap, len; int ok; } W;

static void w_bytes(W *w, const void *b, size_t n)
{
    if (!w->ok || w->len + n > w->cap) { w->ok = 0; return; }
    memcpy(w->p + w->len, b, n); w->len += n;
}
static void w_u8(W *w, uint8_t v) { w_bytes(w, &v, 1); }
static void w_le(W *w, uint64_t v, int n) { uint8_t b[8]; for (int i=0;i<n;i++) b[i]=(uint8_t)(v>>(8*i)); w_bytes(w,b,n); }
static void w_u16be(W *w, uint16_t v) { uint8_t b[2]={(uint8_t)(v>>8),(uint8_t)v}; w_bytes(w,b,2); }
static void w_varint(W *w, uint64_t v)
{
    if (v < 0xfd) w_u8(w,(uint8_t)v);
    else if (v <= 0xffff) { w_u8(w,0xfd); w_le(w,v,2); }
    else if (v <= 0xffffffffULL) { w_u8(w,0xfe); w_le(w,v,4); }
    else { w_u8(w,0xff); w_le(w,v,8); }
}
static void w_varstr(W *w, const char *s)
{
    size_t n = s ? strlen(s) : 0;
    w_varint(w, n);
    w_bytes(w, s, n);
}

/* ── bounded reader ──────────────────────────────────────────── */
typedef struct { const uint8_t *p; size_t len, off; int bad; } R;

/* Subtract rather than add: off is always <= len, so len - off cannot wrap,
   whereas off + n can for an n taken from a varint. */
static void r_need(R *r, size_t n) { if (n > r->len - r->off) r->bad = 1; }
static uint64_t r_le(R *r, int n)
{
    r_need(r, (size_t)n); if (r->bad) return 0;
    uint64_t v = 0; for (int i=0;i<n;i++) v |= (uint64_t)r->p[r->off+i] << (8*i);
    r->off += (size_t)n; return v;
}
static uint16_t r_u16be(R *r)
{
    r_need(r, 2); if (r->bad) return 0;
    uint16_t v = (uint16_t)(r->p[r->off]<<8 | r->p[r->off+1]); r->off += 2; return v;
}
static void r_bytes(R *r, uint8_t *out, size_t n)
{
    r_need(r, n); if (r->bad) return;
    memcpy(out, r->p + r->off, n); r->off += n;
}
static uint64_t r_varint(R *r)
{
    uint8_t pfx = (uint8_t)r_le(r, 1); if (r->bad) return 0;
    if (pfx < 0xfd) return pfx;
    if (pfx == 0xfd) return r_le(r, 2);
    if (pfx == 0xfe) return r_le(r, 4);
    return r_le(r, 8);
}

void kw_netaddr_ipv4(uint8_t out[16], uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    memset(out, 0, 16);
    out[10] = 0xff; out[11] = 0xff;
    out[12] = a; out[13] = b; out[14] = c; out[15] = d;
}

size_t kw_msg_version_build(const kw_msg_version *v, uint8_t *out, size_t outcap)
{
    W w = { out, outcap, 0, 1 };
    w_le(&w, (uint64_t)(uint32_t)v->version, 4);
    w_le(&w, v->services, 8);
    w_le(&w, (uint64_t)v->timestamp, 8);
    w_le(&w, v->recv_services, 8); w_bytes(&w, v->recv_ip, 16); w_u16be(&w, v->recv_port);
    w_le(&w, v->from_services, 8); w_bytes(&w, v->from_ip, 16); w_u16be(&w, v->from_port);
    w_le(&w, v->nonce, 8);
    w_varstr(&w, v->user_agent);
    w_le(&w, (uint64_t)(uint32_t)v->start_height, 4);
    if (v->version >= 70001) w_u8(&w, v->relay);
    return w.ok ? w.len : 0;
}

int kw_msg_version_parse(const uint8_t *in, size_t len, kw_msg_version *v,
                         char *ua, size_t uacap)
{
    R r = { in, len, 0, 0 };
    memset(v, 0, sizeof *v);
    v->version       = (int32_t)r_le(&r, 4);
    v->services      = r_le(&r, 8);
    v->timestamp     = (int64_t)r_le(&r, 8);
    v->recv_services = r_le(&r, 8); r_bytes(&r, v->recv_ip, 16); v->recv_port = r_u16be(&r);
    v->from_services = r_le(&r, 8); r_bytes(&r, v->from_ip, 16); v->from_port = r_u16be(&r);
    v->nonce         = r_le(&r, 8);
    uint64_t ualen = r_varint(&r);
    if (r.bad || ualen >= uacap) return 0;
    r_bytes(&r, (uint8_t *)ua, (size_t)ualen);
    if (r.bad) return 0;
    ua[ualen] = '\0';
    v->user_agent = ua;
    v->start_height = (int32_t)r_le(&r, 4);
    if (v->version >= 70001) {
        if (r.off < r.len) v->relay = (uint8_t)r_le(&r, 1);
        else v->relay = 1;               /* absent means relay, per BIP37 */
    }
    return r.bad ? 0 : 1;
}

size_t kw_msg_ping_build(uint64_t nonce, uint8_t *out, size_t outcap)
{
    W w = { out, outcap, 0, 1 };
    w_le(&w, nonce, 8);
    return w.ok ? w.len : 0;
}

int kw_msg_ping_parse(const uint8_t *in, size_t len, uint64_t *nonce)
{
    R r = { in, len, 0, 0 };
    uint64_t n = r_le(&r, 8);
    if (r.bad) return 0;
    *nonce = n;
    return 1;
}
