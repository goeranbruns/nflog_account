/*
    nflog_account (traffic accounting via netfilter_log)
    nflog_account Copyright (C) 2024-2025 by Goeran Bruns
*/

/*
    This file is part of nflog_account.
    nflog_account is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    nflog_account is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with nflog_account. If not, see <https://www.gnu.org/licenses/>.
*/
#ifndef NLA_SOCKET_H
#define NLA_SOCKET_H

#include <netinet/ip.h>

#define CLIENT_PRINT 1
#define CLIENT_DISCONNECT 2
#define SOCKET_FLUSH 4
#define HOST_FLUSH 8

#define CLIENT_CMD_FLUSH "flush"
#define CLIENT_CMD_STATS "stats"

int socket_init(char *);
void socket_shutdown(int, char *);
int socket_handle(struct pollfd);
int client_handle(struct pollfd, uint32_t *);

#endif