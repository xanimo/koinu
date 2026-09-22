/* koinu.dog - dogecoin p2p message framing
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "proto.h"
#include "sha2.h"
#include "mem.h"

#include <string.h>

static void put_le32(uint8_t *o, uint32_t v)
{
    o[0]=(uint8_t)v; o[1]=(uint8_t)(v>>8); o[2]=(uint8_t)(v>>16); o[3]=(uint8_t)(v>>24);
}
static uint32_t get_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}

static void checksum(const uint8_t *payload, size_t plen, uint8_t out[4])
{
    uint8_t h[KW_SHA256_LEN];
    kw_hash256(payload, plen, h);
    memcpy(out, h, 4);
}

size_t kw_msg_serialize(uint32_t magic, const char *cmd,
                        const uint8_t *payload, size_t plen,
                        uint8_t *out, size_t outcap)
{
    size_t cmdlen = strlen(cmd);
    if (cmdlen > KW_MSG_CMD) return 0;
    if (plen > KW_MSG_MAX_PAYLOAD) return 0;
    if (KW_MSG_HDR + plen > outcap) return 0;

    put_le32(out, magic);
    memset(out + 4, 0, KW_MSG_CMD);
    memcpy(out + 4, cmd, cmdlen);
    put_le32(out + 16, (uint32_t)plen);
    checksum(payload, plen, out + 20);
    if (plen) memcpy(out + KW_MSG_HDR, payload, plen);
    return KW_MSG_HDR + plen;
}

int kw_msg_parse(uint32_t magic, const uint8_t *buf, size_t buflen,
                 char cmd[13], const uint8_t **payload, size_t *plen)
{
    if (buflen < KW_MSG_HDR) return 0;
    if (get_le32(buf) != magic) return -1;

    uint32_t len = get_le32(buf + 16);
    if (len > KW_MSG_MAX_PAYLOAD) return -1;
    if (buflen < (size_t)KW_MSG_HDR + len) return 0;   /* wait for the rest */

    uint8_t want[4];
    checksum(buf + KW_MSG_HDR, len, want);
    if (kw_memcmp_ct(want, buf + 20, 4) != 0) return -1;

    memcpy(cmd, buf + 4, KW_MSG_CMD);
    cmd[KW_MSG_CMD] = '\0';           /* command is NUL-padded to 12 bytes */

    if (payload) *payload = buf + KW_MSG_HDR;
    if (plen)    *plen = len;
    return (int)(KW_MSG_HDR + len);
}
