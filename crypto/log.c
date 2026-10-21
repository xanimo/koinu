/* koinu.dog - where the library's diagnostics go, if anywhere
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "log.h"

#include <stdarg.h>
#include <stdio.h>

static kw_log_fn log_fn;
static void    *log_ctx;

void kw_log_set(kw_log_fn fn, void *ctx)
{
    log_fn = fn;
    log_ctx = ctx;
}

int kw_log_wants(kw_log_level level)
{
    (void)level;
    return log_fn != NULL;
}

void kw_logf(kw_log_level level, const char *fmt, ...)
{
    /* Longer than any message here, and truncated rather than grown: a
       diagnostic is not worth an allocation that can fail on the path where
       something has already gone wrong. */
    char line[512];
    va_list ap;

    if (!log_fn) return;
    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    log_fn(log_ctx, level, line);
}
