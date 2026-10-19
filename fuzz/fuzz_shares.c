/* koinu.dog - fuzz harnesses for the two share formats
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * SLIP-39 and codex32 decode and combine on bytes nobody wrote. A share is
 * typed in by a person rather than handed over by a peer, so these are not
 * the wire parsers; they are still parsers of text the wallet did not produce,
 * and a share set can arrive in a file from whoever holds the other shares.
 *
 * The first byte picks the target and the rest splits on newlines into
 * strings, so one corpus covers all four entry points. Seed it from the
 * strings in test/slip39_vectors.h and test/codex32_vectors.h: from noise the
 * checksums refuse everything and combine is never reached.
 *
 * Built with libFuzzer (make fuzz). */

#include "codex32.h"
#include "slip39.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAX_STRINGS 64

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const char *p[MAX_STRINGS];
    uint8_t out[64];
    char *buf, *s, *nl;
    size_t k = 0, outlen = 0;

    if (size < 2 || size > 8192) return 0;
    buf = (char *)malloc(size);
    if (!buf) return 0;
    memcpy(buf, data + 1, size - 1);
    buf[size - 1] = '\0';

    for (s = buf; s && k < MAX_STRINGS; s = nl) {
        nl = strchr(s, '\n');
        if (nl) *nl++ = '\0';
        p[k++] = s;
    }

    switch (data[0] & 3) {
    case 0: {
        kw_slip39_share sh;
        /* A share that decodes has to encode back to something that decodes to
           the same share, which is the property no crash-only run can check. */
        if (kw_slip39_decode(p[0], &sh) == KW_SLIP39_OK) {
            char m[KW_SLIP39_MNEMONIC_MAX];
            kw_slip39_share back;
            if (kw_slip39_encode(&sh, m, sizeof m) == KW_SLIP39_OK &&
                kw_slip39_decode(m, &back) == KW_SLIP39_OK &&
                memcmp(&sh, &back, sizeof sh) != 0)
                abort();
        }
        break;
    }
    case 1:
        kw_slip39_combine(p, k, "", out, sizeof out, &outlen);
        break;
    case 2: {
        kw_codex32 c;
        if (kw_codex32_decode(p[0], &c) == KW_CODEX32_OK) {
            char str[KW_CODEX32_MAX_LEN];
            kw_codex32 back;
            kw_codex32_seed(&c, out, sizeof out, &outlen);
            /* Field by field rather than over the struct: a comparison that
               reads the alignment hole is a comparison of whatever the stack
               held, which is how this check first reported a crash that would
               not reproduce. */
            if (kw_codex32_encode(&c, str, sizeof str) == KW_CODEX32_OK &&
                kw_codex32_decode(str, &back) == KW_CODEX32_OK &&
                (back.nsym != c.nsym || memcmp(back.sym, c.sym, c.nsym) != 0))
                abort();
        }
        break;
    }
    case 3:
        kw_codex32_combine(p, k, out, sizeof out, &outlen);
        break;
    }

    free(buf);
    return 0;
}
