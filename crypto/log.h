/* koinu.dog - where the library's diagnostics go, if anywhere
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * A library that writes to stderr decides something that is not its to decide.
 * A caller may be a daemon with no terminal, a gui, a wasm build with no stderr
 * at all, or a program that wants its own format: all of them get a line of
 * koinu's prose in the middle of their own output and no way to stop it.
 *
 * So nothing here prints. kw_log_set installs a sink and no sink means silence,
 * which is the default a library should have. kw, kwd and kwui install one that
 * writes to stderr, so the programs behave exactly as before.
 *
 * Two levels, because the messages are two kinds. KW_LOG_ERROR is a refusal or
 * a fact the user needs whether they asked or not, such as a secret that could
 * not be locked into ram. KW_LOG_TRACE is progress, which is what --verbose
 * used to mean. The sink decides what to do with each rather than a global flag
 * deciding whether the library formats it. */

#ifndef KOINU_LOG_H
#define KOINU_LOG_H

typedef enum {
    KW_LOG_ERROR = 0,
    KW_LOG_TRACE = 1
} kw_log_level;

/* (line) has no trailing newline and does not outlive the call. */
typedef void (*kw_log_fn)(void *ctx, kw_log_level level, const char *line);

/* Install a sink, or NULL for silence. Not thread safe and not meant to be:
   call it once at startup, before anything that might log. */
void kw_log_set(kw_log_fn fn, void *ctx);

/* 1 if a sink would take this level, so a caller can skip assembling a message
   nobody will read. */
int kw_log_wants(kw_log_level level);

/* Format one line to the installed sink. A no-op with no sink. */
void kw_logf(kw_log_level level, const char *fmt, ...);

#endif /* KOINU_LOG_H */
