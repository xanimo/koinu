/* dogewallet - dogecoin p2p message framing
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * The 24-byte message header: magic(4) command(12) length(4) checksum(4),
 * followed by the payload. The checksum is the first four bytes of the payload's
 * double-SHA256. Serialization only here; the transport and the message bodies
 * build on top. */

#ifndef DOGEWALLET_PROTO_H
#define DOGEWALLET_PROTO_H

#include <stddef.h>
#include <stdint.h>

#define DW_MSG_HDR         24
#define DW_MSG_CMD         12
#define DW_MSG_MAX_PAYLOAD (32u * 1024u * 1024u)   /* refuse absurd frames */

/* Frame a message into (out): 24-byte header plus payload. (cmd) is an ASCII
   command up to 12 bytes. Returns the total length (24 + plen), or 0 if the
   command is too long or (out) cannot hold it. (payload) may be NULL when plen
   is 0. */
size_t dw_msg_serialize(uint32_t magic, const char *cmd,
                        const uint8_t *payload, size_t plen,
                        uint8_t *out, size_t outcap);

/* Parse one framed message from the front of (buf). Returns:
     >0  bytes consumed (24 + payload length); (cmd) gets the NUL-terminated
         command, (payload) points into (buf), (plen) its length,
      0  buffer does not yet hold a full message (read more),
     -1  wrong magic, oversize length, or a checksum mismatch.
   cmd must have room for 13 bytes. */
int dw_msg_parse(uint32_t magic, const uint8_t *buf, size_t buflen,
                 char cmd[13], const uint8_t **payload, size_t *plen);

#endif /* DOGEWALLET_PROTO_H */
