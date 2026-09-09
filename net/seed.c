/* koinu.dog - DNS seed resolution
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr */

#include "seed.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>

size_t kw_seed_resolve(const kw_chainparams *cp, char out[][KW_SEED_ADDRLEN], size_t max)
{
    if (!cp->dns_seeds || !max) return 0;

    size_t n = 0;
    for (size_t s = 0; s < cp->nseeds && n < max; s++) {
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(cp->dns_seeds[s], NULL, &hints, &res) != 0) continue;

        for (struct addrinfo *a = res; a && n < max; a = a->ai_next) {
            char ip[KW_SEED_ADDRLEN];
            struct sockaddr_in *sin = (struct sockaddr_in *)a->ai_addr;
            if (!inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof ip)) continue;
            int dup = 0;
            for (size_t i = 0; i < n && !dup; i++) dup = strcmp(out[i], ip) == 0;
            if (!dup) { memcpy(out[n], ip, strlen(ip) + 1); n++; }
        }
        freeaddrinfo(res);
    }
    return n;
}
