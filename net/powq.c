/* koinu.dog - the validator pool
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * A bounded ring of jobs, one mutex, and two conditions: one for a worker waiting on
 * work, one for a producer waiting on room. Workers take up to KW_SCRYPT_BATCH jobs
 * at a time because that is what the wide scrypt core wants; taking one at a time
 * would leave it running the single-hash path and cost most of the speed.
 *
 * The first failure wins and stops the pool. A chain with a bad header is not a chain
 * worth finishing, and reporting the lowest height rather than whichever worker
 * noticed first makes the answer the same on every run. */

#include "powq.h"
#include "auxpow.h"
#include "pow.h"
#include "scrypt.h"
#include "sha2.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    uint32_t height;
    uint8_t  header[80];
    uint8_t *aux;
    size_t   auxlen;
} job;

struct kw_powq {
    pthread_mutex_t  m;
    pthread_cond_t   has_work, has_room;
    job             *ring;
    size_t           depth, head, tail, count;
    int              stopping, threads;
    pthread_t       *tid;

    uint64_t         checked;
    int              failed;
    uint32_t         bad_height;
};

static void sha256d(const uint8_t *in, size_t len, uint8_t out[32])
{
    uint8_t once[32];
    kw_sha256(in, len, once);
    kw_sha256(once, 32, out);
}

/* Record a header that did not prove its work, keeping the lowest height so the
   answer does not depend on which worker got there first. */
static void mark_bad(kw_powq *q, uint32_t height)
{
    if (!q->failed || height < q->bad_height) q->bad_height = height;
    q->failed = 1;
    pthread_cond_broadcast(&q->has_work);   /* the others should stop too */
    pthread_cond_broadcast(&q->has_room);
}

static void *worker(void *arg)
{
    kw_powq *q = (kw_powq *)arg;
    void *scratch = malloc((size_t)KW_SCRYPT_SCRATCH * KW_SCRYPT_BATCH);
    job mine[KW_SCRYPT_BATCH];

    for (;;) {
        size_t n = 0;
        pthread_mutex_lock(&q->m);
        while (q->count == 0 && !q->stopping && !q->failed)
            pthread_cond_wait(&q->has_work, &q->m);
        if (q->failed || (q->count == 0 && q->stopping)) { pthread_mutex_unlock(&q->m); break; }
        while (n < KW_SCRYPT_BATCH && q->count) {
            mine[n++] = q->ring[q->head];
            q->head = (q->head + 1) % q->depth;
            q->count--;
        }
        pthread_cond_broadcast(&q->has_room);
        pthread_mutex_unlock(&q->m);

        /* Work out what each job needs hashed: its own header, or its parent's when
           the proof is merged-mined. The structural rules are checked here, since
           they are cheap and a job that fails them needs no hashing at all. */
        uint8_t batch[KW_SCRYPT_BATCH][80];
        uint8_t out[KW_SCRYPT_BATCH][32];
        uint32_t bits[KW_SCRYPT_BATCH];
        uint32_t at[KW_SCRYPT_BATCH];
        size_t want = 0;
        int bad = 0;
        uint32_t bad_at = 0;

        for (size_t i = 0; i < n; i++) {
            uint8_t id[32];
            sha256d(mine[i].header, 80, id);
            uint32_t nbits = kw_header_bits(mine[i].header);

            if (mine[i].aux) {
                kw_auxpow ap;
                size_t off = 0;
                if (!kw_auxpow_parse(mine[i].aux, mine[i].auxlen, &off, &ap) ||
                    !kw_auxpow_check_structure(&ap, id, KW_AUXPOW_CHAIN_ID)) {
                    if (!bad || mine[i].height < bad_at) bad_at = mine[i].height;
                    bad = 1;
                    continue;
                }
                memcpy(batch[want], ap.parent, 80);
            } else {
                memcpy(batch[want], mine[i].header, 80);
            }
            bits[want] = nbits;
            at[want] = mine[i].height;
            want++;
        }

        if (want && !kw_scrypt_pow_batch((const uint8_t *)batch, want, (uint8_t *)out, scratch)) {
            bad = 1;
            if (!bad_at) bad_at = at[0];
        } else {
            for (size_t i = 0; i < want; i++)
                if (!kw_pow_check(out[i], bits[i])) {
                    if (!bad || at[i] < bad_at) bad_at = at[i];
                    bad = 1;
                }
        }

        for (size_t i = 0; i < n; i++) free(mine[i].aux);

        pthread_mutex_lock(&q->m);
        q->checked += n;
        if (bad) mark_bad(q, bad_at);
        pthread_mutex_unlock(&q->m);
        if (bad) break;
    }

    free(scratch);
    return NULL;
}

kw_powq *kw_powq_start(int nthreads, size_t depth)
{
    if (nthreads <= 0) {
        long n = sysconf(_SC_NPROCESSORS_ONLN);
        /* the work is issue-bound, so hyperthreads add nothing: half the reported
           count is the usual number of cores */
        nthreads = n > 1 ? (int)(n / 2) : 1;
        if (nthreads < 1) nthreads = 1;
    }
    if (depth < (size_t)KW_SCRYPT_BATCH * (size_t)nthreads)
        depth = (size_t)KW_SCRYPT_BATCH * (size_t)nthreads;

    kw_powq *q = (kw_powq *)calloc(1, sizeof *q);
    if (!q) return NULL;
    q->ring = (job *)calloc(depth, sizeof *q->ring);
    q->tid = (pthread_t *)calloc((size_t)nthreads, sizeof *q->tid);
    if (!q->ring || !q->tid) { free(q->ring); free(q->tid); free(q); return NULL; }
    q->depth = depth;
    pthread_mutex_init(&q->m, NULL);
    pthread_cond_init(&q->has_work, NULL);
    pthread_cond_init(&q->has_room, NULL);

    for (int i = 0; i < nthreads; i++) {
        if (pthread_create(&q->tid[i], NULL, worker, q) != 0) break;
        q->threads++;
    }
    if (q->threads == 0) {
        pthread_mutex_destroy(&q->m);
        pthread_cond_destroy(&q->has_work);
        pthread_cond_destroy(&q->has_room);
        free(q->ring); free(q->tid); free(q);
        return NULL;
    }
    return q;
}

int kw_powq_threads(const kw_powq *q) { return q ? q->threads : 0; }

int kw_powq_submit(kw_powq *q, uint32_t height, const uint8_t header[80],
                   const uint8_t *aux, size_t auxlen)
{
    if (!q || !header) return 0;

    uint8_t *copy = NULL;
    if (aux && auxlen) {
        copy = (uint8_t *)malloc(auxlen);
        if (!copy) return 0;
        memcpy(copy, aux, auxlen);
    }

    pthread_mutex_lock(&q->m);
    while (q->count == q->depth && !q->failed && !q->stopping)
        pthread_cond_wait(&q->has_room, &q->m);
    if (q->failed || q->stopping) {          /* nothing more is worth queueing */
        pthread_mutex_unlock(&q->m);
        free(copy);
        return 0;
    }
    job *j = &q->ring[q->tail];
    j->height = height;
    memcpy(j->header, header, 80);
    j->aux = copy;
    j->auxlen = copy ? auxlen : 0;
    q->tail = (q->tail + 1) % q->depth;
    q->count++;
    pthread_cond_signal(&q->has_work);
    pthread_mutex_unlock(&q->m);
    return 1;
}

int kw_powq_finish(kw_powq *q, uint64_t *checked, uint32_t *bad_height)
{
    if (!q) return 0;

    pthread_mutex_lock(&q->m);
    q->stopping = 1;
    pthread_cond_broadcast(&q->has_work);
    pthread_cond_broadcast(&q->has_room);
    pthread_mutex_unlock(&q->m);

    for (int i = 0; i < q->threads; i++) pthread_join(q->tid[i], NULL);

    /* a failure stops the workers mid-queue, so anything left holds a blob to free */
    while (q->count) {
        free(q->ring[q->head].aux);
        q->head = (q->head + 1) % q->depth;
        q->count--;
    }

    int ok = !q->failed;
    if (checked) *checked = q->checked;
    if (bad_height) *bad_height = q->bad_height;

    pthread_mutex_destroy(&q->m);
    pthread_cond_destroy(&q->has_work);
    pthread_cond_destroy(&q->has_room);
    free(q->ring);
    free(q->tid);
    free(q);
    return ok;
}
