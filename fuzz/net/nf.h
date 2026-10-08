/* netfuzz: shared pieces for the stateful koinu peer harnesses the stateful network harnesses.
   A fake peer is a thread on one end of a socketpair that writes a pre-built byte
   stream (the "script") in fuzzer-chosen chunks and drains whatever the library
   sends, so neither side can block the other. When the script is written the
   peer shuts down its write side, so the library sees EOF rather than a stall. */
#ifndef NF_H
#define NF_H
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include "chainparams.h"
#include "headers.h"
#include "peer.h"
#include "proto.h"
#include "pow.h"
#include "scrypt.h"
#include "sha2.h"
#include "gcs.h"
#include "siphash.h"

/* ---------------- input consumer ---------------- */
typedef struct { const uint8_t *p; size_t n; } nf_in;
static inline uint8_t in8(nf_in *in) { if (!in->n) return 0; uint8_t v = *in->p++; in->n--; return v; }
static inline uint16_t in16(nf_in *in) { uint16_t a = in8(in); return (uint16_t)(a | (uint16_t)in8(in) << 8); }
static inline uint32_t in32(nf_in *in) { uint32_t a = in16(in); return a | (uint32_t)in16(in) << 16; }
static inline uint64_t in64(nf_in *in) { uint64_t a = in32(in); return a | (uint64_t)in32(in) << 32; }
static inline const uint8_t *intake(nf_in *in, size_t want, size_t *got)
{ if (want > in->n) want = in->n; const uint8_t *r = in->p; in->p += want; in->n -= want; *got = want; return r; }

/* ---------------- growable byte buffer ---------------- */
typedef struct { uint8_t *b; size_t n, cap; } nf_buf;
static inline void nb_put(nf_buf *x, const void *p, size_t n)
{
    if (x->n + n > x->cap) {
        size_t nc = x->cap ? x->cap : 4096;
        while (nc < x->n + n) nc *= 2;
        uint8_t *nb2 = (uint8_t *)realloc(x->b, nc);
        if (!nb2) { fprintf(stderr, "NF-HARNESS realloc %zu failed\n", nc); abort(); }
        x->b = nb2; x->cap = nc;
    }
    if (n) memcpy(x->b + x->n, p, n);
    x->n += n;
}
static inline void nb_u8(nf_buf *x, uint8_t v) { nb_put(x, &v, 1); }
static inline void nb_le32(nf_buf *x, uint32_t v) { uint8_t b[4]; for (int i = 0; i < 4; i++) b[i] = (uint8_t)(v >> (8 * i)); nb_put(x, b, 4); }
static inline void nb_le64(nf_buf *x, uint64_t v) { uint8_t b[8]; for (int i = 0; i < 8; i++) b[i] = (uint8_t)(v >> (8 * i)); nb_put(x, b, 8); }
static inline void nb_varint(nf_buf *x, uint64_t v)
{
    if (v < 0xfd) nb_u8(x, (uint8_t)v);
    else if (v <= 0xffff) { nb_u8(x, 0xfd); nb_u8(x, (uint8_t)v); nb_u8(x, (uint8_t)(v >> 8)); }
    else if (v <= 0xffffffffu) { nb_u8(x, 0xfe); nb_le32(x, (uint32_t)v); }
    else { nb_u8(x, 0xff); nb_le64(x, v); }
}
static inline void nb_free(nf_buf *x) { free(x->b); memset(x, 0, sizeof *x); }

/* frame a message onto (out). fix=1: correct length and checksum. */
static inline void nf_frame(nf_buf *out, uint32_t magic, const char *cmd,
                            const uint8_t *pl, size_t pn, int fix, uint32_t badlen, uint32_t badck)
{
    uint8_t h[24]; memset(h, 0, sizeof h);
    for (int i = 0; i < 4; i++) h[i] = (uint8_t)(magic >> (8 * i));
    size_t cl = strlen(cmd); if (cl > 12) cl = 12;
    memcpy(h + 4, cmd, cl);
    uint32_t len = fix ? (uint32_t)pn : badlen;
    for (int i = 0; i < 4; i++) h[16 + i] = (uint8_t)(len >> (8 * i));
    uint8_t d[32]; kw_hash256(pl, pn, d);
    if (fix) memcpy(h + 20, d, 4);
    else for (int i = 0; i < 4; i++) h[20 + i] = (uint8_t)(badck >> (8 * i));
    nb_put(out, h, 24);
    nb_put(out, pl, pn);
}

/* ---------------- fake peer ---------------- */
typedef struct {
    int fd;                 /* the peer's end */
    nf_buf script;          /* bytes to write */
    size_t *cuts; size_t ncuts;   /* chunk boundaries (ascending offsets) */
    nf_buf got;             /* what the library sent, if record=1 */
    int record;
    pthread_t th;
    int started;
} nf_peer;

static void *nf_peer_main(void *arg)
{
    nf_peer *pp = (nf_peer *)arg;
    size_t off = 0, ci = 0;
    int wr_open = 1;
    uint8_t rb[65536];
    for (;;) {
        struct pollfd pf = { pp->fd, POLLIN, 0 };
        if (wr_open && off < pp->script.n) pf.events |= POLLOUT;
        int pr = poll(&pf, 1, 2000);
        if (pr < 0) { if (errno == EINTR) continue; break; }
        if (pr == 0) continue;
        if (pf.revents & POLLIN) {
            ssize_t r = read(pp->fd, rb, sizeof rb);
            if (r <= 0) break;                      /* library closed */
            if (pp->record) nb_put(&pp->got, rb, (size_t)r);
        }
        if ((pf.revents & POLLOUT) && wr_open && off < pp->script.n) {
            size_t end = pp->script.n;
            while (ci < pp->ncuts && pp->cuts[ci] <= off) ci++;
            if (ci < pp->ncuts && pp->cuts[ci] < end) end = pp->cuts[ci];
            ssize_t w = send(pp->fd, pp->script.b + off, end - off, MSG_NOSIGNAL | MSG_DONTWAIT);
            if (w < 0) { if (errno == EAGAIN || errno == EINTR) continue; wr_open = 0; shutdown(pp->fd, SHUT_WR); }
            else { off += (size_t)w; if (ci < pp->ncuts && off >= pp->cuts[ci]) sched_yield(); }
        }
        if ((pf.revents & (POLLHUP | POLLERR)) && !(pf.revents & POLLIN)) break;
        if (wr_open && off >= pp->script.n) { wr_open = 0; shutdown(pp->fd, SHUT_WR); }
    }
    return NULL;
}

/* make the pair; (lib) gets the library's end wrapped as a kw_peer */
static inline int nf_peer_open(nf_peer *pp, kw_peer *lib, const kw_chainparams *cp)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return 0;
    struct timeval tv = { 1, 0 };
    setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(sv[0], SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    pp->fd = sv[1];
    if (!kw_peer_from_fd(lib, cp->magic, sv[0])) { close(sv[0]); close(sv[1]); return 0; }
    lib->cp = cp;
    return 1;
}
static inline void nf_peer_start(nf_peer *pp)
{
    pp->started = pthread_create(&pp->th, NULL, nf_peer_main, pp) == 0;
}
/* call after the library is done with its end and has closed it */
static inline void nf_peer_finish(nf_peer *pp)
{
    if (pp->started) pthread_join(pp->th, NULL);
    close(pp->fd);
    nb_free(&pp->script); nb_free(&pp->got); free(pp->cuts);
    memset(pp, 0, sizeof *pp);
}
static inline void nf_peer_cut(nf_peer *pp)    /* a chunk boundary at the current end */
{
    pp->cuts = (size_t *)realloc(pp->cuts, (pp->ncuts + 1) * sizeof *pp->cuts);
    pp->cuts[pp->ncuts++] = pp->script.n;
}

/* ---------------- headers and mining ---------------- */
#define NF_EASY 0x207fffffu
#define NF_HARD 0x20550000u

static inline void nf_hdr_fill(uint8_t raw[80], uint32_t ver, const uint8_t prev[32],
                               const uint8_t merkle[32], uint32_t time, uint32_t bits, uint32_t nonce)
{
    for (int i = 0; i < 4; i++) raw[i] = (uint8_t)(ver >> (8 * i));
    memcpy(raw + 4, prev, 32);
    memcpy(raw + 36, merkle, 32);
    for (int i = 0; i < 4; i++) raw[68 + i] = (uint8_t)(time >> (8 * i));
    for (int i = 0; i < 4; i++) raw[72 + i] = (uint8_t)(bits >> (8 * i));
    for (int i = 0; i < 4; i++) raw[76 + i] = (uint8_t)(nonce >> (8 * i));
}
static inline int nf_pow_ok(const uint8_t raw[80])
{
    uint8_t h[32];
    if (!kw_scrypt_pow(raw, h, NULL)) return 0;
    return kw_pow_check(h, kw_header_bits(raw));
}
/* search nonces from the current one for a header that does (want=1) or does not
   (want=0) meet its target. Bounded; returns 1 on success. */
static inline int nf_mine(uint8_t raw[80], int want)
{
    uint32_t n0 = (uint32_t)raw[76] | (uint32_t)raw[77] << 8 | (uint32_t)raw[78] << 16 | (uint32_t)raw[79] << 24;
    for (uint32_t k = 0; k < 64; k++) {
        uint32_t n = n0 + k;
        for (int i = 0; i < 4; i++) raw[76 + i] = (uint8_t)(n >> (8 * i));
        if (nf_pow_ok(raw) == want) return 1;
    }
    return 0;
}
static inline void nf_genesis(const kw_chainparams *cp, uint8_t out[32])
{
    for (int i = 0; i < 32; i++) {
        unsigned v; sscanf(cp->genesis + 2 * i, "%2x", &v);
        out[31 - i] = (uint8_t)v;
    }
}
static inline void nf_hex_rev(const uint8_t in[32], char out[65])
{
    static const char d[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) { out[2 * i] = d[in[31 - i] >> 4]; out[2 * i + 1] = d[in[31 - i] & 15]; }
    out[64] = 0;
}

/* invariant helpers over a header store */
static inline int nf_store_links(const kw_headerstore *s, const uint8_t genesis[32], size_t *bad)
{
    for (size_t i = 0; i < s->count; i++) {
        uint8_t h[32]; kw_hash256(s->h[i].raw, 80, h);
        if (memcmp(h, s->h[i].hash, 32)) { *bad = i + 1; return 0; }
        const uint8_t *want = i ? s->h[i - 1].hash : genesis;
        if (memcmp(s->h[i].raw + 4, want, 32)) { *bad = i + 1; return 0; }
    }
    return 1;
}

/* ---------------- merkle and GCS (independent of the library) ---------------- */
static inline void nf_merkle(uint8_t (*ids)[32], size_t n, uint8_t root[32])
{
    if (!n) { memset(root, 0, 32); return; }
    uint8_t (*h)[32] = (uint8_t (*)[32])malloc(n * 32);
    memcpy(h, ids, n * 32);
    while (n > 1) {
        size_t w = 0;
        for (size_t i = 0; i < n; i += 2, w++) {
            uint8_t cat[64];
            memcpy(cat, h[i], 32);
            memcpy(cat + 32, (i + 1 < n) ? h[i + 1] : h[i], 32);
            kw_hash256(cat, 64, h[w]);
        }
        n = w;
    }
    memcpy(root, h[0], 32);
    free(h);
}

static int nf_cmp64(const void *a, const void *b)
{ uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b; return (x > y) - (x < y); }

/* BIP158 basic filter over (items) for (bh). */
static inline void nf_gcs_build(nf_buf *out, const uint8_t bh[32],
                                const uint8_t *const *items, const size_t *lens, size_t n)
{
    nb_varint(out, n);
    if (!n) return;
    uint64_t *v = (uint64_t *)malloc(n * sizeof *v);
    for (size_t i = 0; i < n; i++) v[i] = kw_gcs_hash(bh, n, items[i], lens[i]);
    qsort(v, n, sizeof *v, nf_cmp64);
    uint8_t acc = 0; int nbits = 0; uint64_t last = 0;
#define PUTBIT(b) do { acc = (uint8_t)((acc << 1) | ((b) & 1)); if (++nbits == 8) { nb_u8(out, acc); acc = 0; nbits = 0; } } while (0)
    for (size_t i = 0; i < n; i++) {
        uint64_t d = v[i] - last; last = v[i];
        uint64_t q = d >> KW_GCS_P;
        for (uint64_t k = 0; k < q; k++) PUTBIT(1);
        PUTBIT(0);
        for (int k = KW_GCS_P - 1; k >= 0; k--) PUTBIT((d >> k) & 1);
    }
    if (nbits) { acc = (uint8_t)(acc << (8 - nbits)); nb_u8(out, acc); }
#undef PUTBIT
    free(v);
}

/* one-shot reporting of a known finding, then silence */
static inline int nf_known(const char *tag, int *done)
{
    if (*done) return 0;
    *done = 1;
    fprintf(stderr, "NF-KNOWN %s (reported once, now disabled)\n", tag);
    return 1;
}
#define NF_FAIL(...) do { fprintf(stderr, "NF-INVARIANT: " __VA_ARGS__); fputc('\n', stderr); abort(); } while (0)


/* ---------------- memoised scrypt (same answers, fewer hashes) ---------------- */
#ifndef NF_CACHE_BITS
#define NF_CACHE_BITS 18
#endif
typedef struct { uint8_t key[32]; uint8_t used, ok; } nf_pc_ent;
static nf_pc_ent *nf_pc;
static pthread_mutex_t nf_pc_m = PTHREAD_MUTEX_INITIALIZER;
static inline int nf_pow_ok_cached(const uint8_t raw[80])
{
    uint8_t k[32]; kw_hash256(raw, 80, k);
    pthread_mutex_lock(&nf_pc_m);
    if (!nf_pc) nf_pc = (nf_pc_ent *)calloc((size_t)1 << NF_CACHE_BITS, sizeof *nf_pc);
    size_t i = ((size_t)k[0] | (size_t)k[1] << 8 | (size_t)k[2] << 16) & (((size_t)1 << NF_CACHE_BITS) - 1);
    if (nf_pc[i].used && !memcmp(nf_pc[i].key, k, 32)) { int r = nf_pc[i].ok; pthread_mutex_unlock(&nf_pc_m); return r; }
    pthread_mutex_unlock(&nf_pc_m);
    int ok = nf_pow_ok(raw);
    pthread_mutex_lock(&nf_pc_m);
    memcpy(nf_pc[i].key, k, 32); nf_pc[i].used = 1; nf_pc[i].ok = (uint8_t)ok;
    pthread_mutex_unlock(&nf_pc_m);
    return ok;
}
static inline int nf_mine_cached(uint8_t raw[80], int want)
{
    uint32_t n0 = (uint32_t)raw[76] | (uint32_t)raw[77] << 8 | (uint32_t)raw[78] << 16 | (uint32_t)raw[79] << 24;
    for (uint32_t k = 0; k < 64; k++) {
        uint32_t n = n0 + k;
        for (int i = 0; i < 4; i++) raw[76 + i] = (uint8_t)(n >> (8 * i));
        if (nf_pow_ok_cached(raw) == want) return 1;
    }
    return 0;
}
#endif
