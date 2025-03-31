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
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <poll.h>
#include <syslog.h>
#include <arpa/inet.h>

#include "nla_socket.h"


int socket_init(char *name)
{
    struct sockaddr_un address;
    struct stat socket_stat;


    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
        fprintf(stderr, "socket\n");
        return -1;
    }


    if (stat(name, &socket_stat) != -1) {
        printf("old socket file found\n");
        if (unlink(name) == -1) {
            fprintf(stderr, "unlink old socket file\n");
            return -1;
        }
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path, name, sizeof(address.sun_path) - 1);
    if (bind(fd, (const struct sockaddr *) &address, sizeof(address)) == -1) {
        fprintf(stderr, "bind\n");
        return -1;
    }

    if (listen(fd, 20) == -1) {
        fprintf(stderr, "listen\n");
        return -1;
    }

    return fd;
}

void socket_shutdown(int fd, char *name)
{
    close(fd);
    unlink(name);

}

int socket_handle(struct pollfd pfd)
{
    int events = pfd.events;
    int rv = 0;
    if (events & POLLIN) {
        rv = accept(pfd.fd, NULL, NULL);
        events ^= POLLIN;
    }

    if (events != 0) {
        syslog(LOG_NOTICE, "socket unhandled events 0x%x", events);
        printf("socket unhandled events 0x%x\n", events);
    }

    return rv;
}

int client_handle(struct pollfd pfd, uint32_t *hostAddr)
{
    int events = pfd.revents;
    int rv = 0;

    if (events & POLLIN) {
        char buf[32];
        // read command in buffer
        int ret = read(pfd.fd, buf, sizeof(buf));
        if (ret == -1) {
            syslog(LOG_WARNING, "error read from client");
            // fprintf(stderr, "error read from client\n");
        } else {
            // 0 terminate buffer
            buf[sizeof(buf) - 1] = 0;
            
            // printf("received \"%s\"\n", buf);
            
            if (strncmp(CLIENT_CMD_STATS, buf, 5) == 0) {
                rv = CLIENT_PRINT | CLIENT_DISCONNECT;
            } else if (strncmp(CLIENT_CMD_FLUSH, buf, 5) == 0) {
                rv = CLIENT_PRINT | CLIENT_DISCONNECT;
                // possible host to flush given
                if (ret > 6) {
                    struct in_addr addr = {
                        .s_addr = 0
                    };
                    // replace trailing line feed with 0
                    for (int i = 6; i < ret; i++) {
                        if (buf[i] == 10) {
                            buf[i] = 0;
                            break;
                        }
                    }
                    // try to parse ip
                    if (inet_pton(AF_INET, &buf[6], &addr) == 1) {
                        *hostAddr = addr.s_addr;
                        rv += HOST_FLUSH;
                    }
                } else {
                    rv += SOCKET_FLUSH;
                }

            } else {
                rv = CLIENT_DISCONNECT;
            }
        }
        events ^= POLLIN;
    }

    if (events & POLLHUP) {
        rv = CLIENT_DISCONNECT;        
        events ^= POLLHUP;
    }

    if (events != 0) {
        syslog(LOG_NOTICE, "client unhandled events 0x%x", events);
        // printf("client unhandled events 0x%x\n", events);
    }

    return rv;
}
