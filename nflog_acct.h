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
#ifndef NFLOG_ACCT_H
#define NFLOG_ACCT_H

#include <libnetfilter_log/libnetfilter_log.h>
#include <netinet/ip.h>

#define MAX_SOCKETNAME_LENGTH 256
#define MAX_NET_LENGTH INET_ADDRSTRLEN + 4
#define HOST_BLOCK_SIZE 10

// accounting network definition
struct net_data {
    uint32_t net; // ip
    uint32_t mask; //mask
};

// acounting data defintion
struct host_data { 
    uint32_t ip; // ip accounted for
    uint64_t packets_src; // packets originated from this ip
    uint64_t bytes_src; // data in bytes originated from this ip
    uint64_t packets_dst; // packets destinated to this ip
    uint64_t bytes_dst; // data in bytes destinatited to this ip
    time_t last_seen; // unix timestamp when packets last went from or to this ip
    time_t first_seen; // unix timestamp when packets first went from or to this ip
};

// socket definition
struct socket_data {
    char name[MAX_SOCKETNAME_LENGTH]; // absolute filename of socket
    int fd; // accociated file descriptor
    struct host_data *hosts; // hosts tracked by this sockets
    int hosts_len; // num of hosts
};

struct account_data {
    int seq;  // receiving sequence number 
    struct net_data *nets;  // networks
    int nets_len;  // num networks
    struct socket_data *sockets;  // sockets
    int sockets_len;  // num sockets
};

struct nflog_handles {
    struct nflog_handle *h; // global nflog handle
    struct nflog_g_handle *gh; // nflog handle for the monitored group
};

// client connected to a sockets
struct client_data {
    int server_fd; // file descriptor accociated to the socket
    int client_fd; // client file descriptor
    int last_seen; // unix timestamp
};

struct host_data* get_host(struct socket_data *, uint32_t);

int nflog_init(struct nflog_handles *, int , nflog_callback *, struct account_data *);
void nflog_shutdown(struct nflog_handles *);
int nflog_handle(struct pollfd pfd, struct nflog_handles *nh);
static int nflog_cb(struct nflog_g_handle *, struct nfgenmsg *, struct nflog_data *, void *);
void set_seen(struct host_data *, time_t);

int init_data(struct account_data *, char [][MAX_NET_LENGTH], int, char [][MAX_SOCKETNAME_LENGTH], int);
void init_host(struct host_data *, int);
void init_hosts(struct socket_data *, int);
void print_data(int, struct socket_data *);
void print_all_data(int, struct account_data *);
void reset_data(struct socket_data *);
void flush_host(struct socket_data *, uint32_t);
void free_data(struct account_data *);
void sockets_shutdown(struct account_data *);


#endif