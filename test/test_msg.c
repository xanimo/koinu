/* koinu.dog - handshake message body tests
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * The version payload is the canonical example from the Bitcoin protocol
 * documentation (user agent /Satoshi:0.7.2/, height 212672), which Dogecoin
 * shares byte-for-byte. */

#include "msg.h"
#include "testutil.h"

#include <stdio.h>
#include <string.h>

/* documented version payload, field-grouped */
static const char *VERSION_HEX =
    "62ea0000"                             /* version 60002        */
    "0100000000000000"                     /* services 1           */
    "11b2d05000000000"                     /* timestamp            */
    "0100000000000000"                     /* addr_recv services   */
    "00000000000000000000ffff00000000"     /* addr_recv ip 0.0.0.0 */
    "0000"                                 /* addr_recv port 0     */
    "0100000000000000"                     /* addr_from services   */
    "00000000000000000000ffff00000000"     /* addr_from ip 0.0.0.0 */
    "0000"                                 /* addr_from port 0     */
    "3b2eb35d8ce61765"                     /* nonce                */
    "0f2f5361746f7368693a302e372e322f"     /* "/Satoshi:0.7.2/"    */
    "c03e0300";                            /* start_height 212672  */

int main(void)
{
    uint8_t buf[256];
    size_t n = kw_test_unhex(VERSION_HEX, buf);

    /* parse the documented payload */
    kw_msg_version v; char ua[64];
    if (!kw_msg_version_parse(buf, n, &v, ua, sizeof ua)) { fprintf(stderr, "FAIL: parse\n"); return 1; }
    if (v.version != 60002)               { fprintf(stderr, "FAIL: version %d\n", v.version); return 1; }
    if (v.services != 1)                  { fprintf(stderr, "FAIL: services\n"); return 1; }
    if (v.timestamp != 0x50d0b211)        { fprintf(stderr, "FAIL: timestamp\n"); return 1; }
    if (v.nonce != 0x6517e68c5db32e3bULL) { fprintf(stderr, "FAIL: nonce %016llx\n", (unsigned long long)v.nonce); return 1; }
    if (strcmp(ua, "/Satoshi:0.7.2/") != 0) { fprintf(stderr, "FAIL: ua %s\n", ua); return 1; }
    if (v.start_height != 212672)         { fprintf(stderr, "FAIL: height %d\n", v.start_height); return 1; }

    /* build the same fields back and match the documented bytes */
    kw_msg_version b;
    memset(&b, 0, sizeof b);
    b.version = 60002; b.services = 1; b.timestamp = 0x50d0b211;
    b.recv_services = 1; kw_netaddr_ipv4(b.recv_ip, 0,0,0,0); b.recv_port = 0;
    b.from_services = 1; kw_netaddr_ipv4(b.from_ip, 0,0,0,0); b.from_port = 0;
    b.nonce = 0x6517e68c5db32e3bULL;
    b.user_agent = "/Satoshi:0.7.2/";
    b.start_height = 212672;
    uint8_t out[256];
    size_t m = kw_msg_version_build(&b, out, sizeof out);
    if (!m) { fprintf(stderr, "FAIL: build\n"); return 1; }
    kw_test_check("version payload", out, m, VERSION_HEX);

    /* a modern version (>= 70001) carries the relay byte and round-trips */
    kw_msg_version m2;
    memset(&m2, 0, sizeof m2);
    m2.version = KW_PROTOCOL_VERSION; m2.services = 0; m2.timestamp = 1700000000;
    kw_netaddr_ipv4(m2.recv_ip, 127,0,0,1); m2.recv_port = 22556;
    kw_netaddr_ipv4(m2.from_ip, 0,0,0,0);
    m2.nonce = 0x0102030405060708ULL; m2.user_agent = "/koinu:0.1/";
    m2.start_height = 5000000; m2.relay = 1;
    uint8_t o2[256]; size_t l2 = kw_msg_version_build(&m2, o2, sizeof o2);
    kw_msg_version p2; char ua2[64];
    if (!l2 || !kw_msg_version_parse(o2, l2, &p2, ua2, sizeof ua2)) { fprintf(stderr, "FAIL: v70015 round trip\n"); return 1; }
    if (p2.version != KW_PROTOCOL_VERSION || p2.recv_port != 22556 || p2.relay != 1 ||
        p2.start_height != 5000000 || strcmp(ua2, "/koinu:0.1/") != 0) {
        fprintf(stderr, "FAIL: v70015 fields\n"); return 1;
    }

    /* ping round trip */
    uint8_t pg[8]; uint64_t pn = 0;
    if (kw_msg_ping_build(0xdeadbeefcafef00dULL, pg, sizeof pg) != 8 ||
        !kw_msg_ping_parse(pg, 8, &pn) || pn != 0xdeadbeefcafef00dULL) {
        fprintf(stderr, "FAIL: ping\n"); return 1;
    }

    if (kw_test_fails()) return 1;
    printf("msg ok: version vector, relay round trip, ping\n");
    return 0;
}
