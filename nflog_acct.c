#define _GNU_SOURCE

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <poll.h>
#include <errno.h>
#include <ctype.h>
#include <syslog.h>
#include <time.h>
#include <string.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include "nla_signal.h"
#include "nla_socket.h"
#include "nflog_acct.h"

#define MAX_FD 32
#define MAX_NETS 5
#define MAX_SOCKETS 5

#define NFLOG_BUFF_SIZE 1048576

int nflog_error_count = 0;
char nflog_buffer[NFLOG_BUFF_SIZE];

void usage(char *prog)
{
    fprintf(stderr, "Usage: %s -n <net/mask> -s <socket file> -g <nflog group>\n", prog);
}

int main(int argc, char *argv[])
{
    char networks[MAX_NETS][MAX_NET_LENGTH];
    int num_networks = 0;
    char sockets[MAX_SOCKETS][MAX_SOCKETNAME_LENGTH];
    int num_sockets = 0;
    int test_mode = 0;
    
    int nflog_group = -1;
    struct pollfd fds[MAX_FD];
    struct client_data clients[MAX_FD];

    struct account_data data = {
        .seq = 0,
        .nets = NULL,
        .nets_len = 0,
        .sockets = NULL,
        .sockets_len = 0
    };

    struct nflog_handles nh;
    int open_fd = 0;
    int opt;

    while ((opt = getopt(argc, argv, "n:s:g:t")) != -1) {
        if (optarg != NULL && isspace(*optarg)) {
            optarg++;
        }
        switch (opt) {
            case 'n':
                if (num_networks == MAX_NETS) {
                    fprintf(stderr, "Too many networks given");
                    exit(EXIT_FAILURE);

                }
                strncpy(networks[num_networks], optarg, MAX_NET_LENGTH);
                networks[num_networks][MAX_NET_LENGTH - 1] = 0;
                num_networks++;
                break;
            case 's':
                if (num_sockets == MAX_SOCKETS) {
                    fprintf(stderr, "Too many networks given");
                    exit(EXIT_FAILURE);
                }
                strncpy(sockets[num_sockets], optarg, MAX_SOCKETNAME_LENGTH);
                sockets[num_sockets][MAX_SOCKETNAME_LENGTH - 1] = 0;
                num_sockets++;
                break;
            case 'g':
                nflog_group = atoi(optarg);
                break;
            case 't':
                test_mode = 1;
                break;
            default:
                usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (num_networks == 0 || num_sockets == 0 || nflog_group < 0 || nflog_group > 65535) {
        fprintf(stderr, "Missing or invalid options\n");
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    openlog(NULL, LOG_PID, LOG_DAEMON);

    if (init_data(&data, networks, num_networks, sockets, num_sockets) == -1) {
        free_data(&data);
        fprintf(stderr, "Invalid network option\n");
        exit(EXIT_FAILURE);
    }

    // init signal file descriptor
    int signal_fd = signal_init();
    if (signal_fd == -1) {
        free_data(&data);
        err(EXIT_FAILURE, "init signal");
    }
    fds[open_fd].fd = signal_fd;
    fds[open_fd].events = POLLIN;
    open_fd++;

    // init sockets file descriptors
    for (int i = 0; i < data.sockets_len; i++) {
        struct socket_data *sd = &data.sockets[i];
        sd->fd = socket_init(sd->name);
        if (sd->fd == -1) {
            sockets_shutdown(&data);
            signal_shutdown(signal_fd);
            free_data(&data);
            err(EXIT_FAILURE, "init socket");
        }
        fds[open_fd].fd = sd->fd;
        fds[open_fd].events = POLLIN;
        open_fd++;
        continue;
    }

    // init client file descriptor
    for (int i = 0; i < MAX_FD; i++) {
        clients[i].client_fd = -1;
    }

    int netfilter_fd = -1;
    if (!test_mode) {
        netfilter_fd = nflog_init(&nh, nflog_group, &nflog_cb, &data);
        if (netfilter_fd == -1) {
            sockets_shutdown(&data);
            signal_shutdown(signal_fd);
            free_data(&data);
            err(EXIT_FAILURE, "init nflog");
        }
    }
    fds[open_fd].fd = netfilter_fd;
    fds[open_fd].events = POLLIN;
    open_fd++;

    // init left over file descriptors with -1
    for (int i = open_fd; i < MAX_FD; i++) {
        fds[i].fd = -1;
    }

    syslog(LOG_INFO, "up and running");
    while (open_fd > 0) {
        int rv = poll(fds, open_fd, -1);

        // time out ?
        if (rv == 0) {
            continue;
        }

        if (rv == -1) {
            syslog(LOG_WARNING, "poll error %d\n", errno);
            break;
        }

        for (int i = 0; i < open_fd; i++) {
            struct pollfd pfd = fds[i];

            // file descriptor not initialized or no events received
            if (pfd.fd == -1 || pfd.revents == 0) {
                continue;
            }

            // netfilter log event
            if (pfd.fd == netfilter_fd) {
                int netfilter_rv = nflog_handle(pfd, &nh);

                if (netfilter_rv == -1) {                    
                    open_fd = 0;
                    break;
                }

                continue;
            }

            // signal event
            if (pfd.fd == signal_fd) {
                int signal_rv = signal_handle(pfd);

                if (signal_rv == -1) {
                    open_fd = 0;
                    break;
                }

                if (signal_rv == SIGNAL_PRINT) {
                    print_all_data(STDOUT_FILENO, &data);
                }

                if (signal_rv == SIGNAL_SHUTDOWN) {
                    syslog(LOG_INFO, "shutdown requested");
                    open_fd = 0;
                    break;
                }

                continue;
            }

            // check for event on sockets
            struct socket_data *sd = NULL;
            for (int j = 0; j < data.sockets_len; j++) {
                if (pfd.fd == data.sockets[j].fd) {
                    sd = &data.sockets[j];
                    break;
                }
            }
            if (sd != NULL) {
                int client_fd = socket_handle(pfd);

                if (0 != client_fd) {
                    // look for a free spot
                    // add client to poll file descriptor
                    // add client socket to socket list
                    int accept = 0;

                    if (open_fd < MAX_FD) {
                        fds[open_fd].fd = client_fd;
                        fds[open_fd].events = POLLIN;
                        open_fd++;
                        accept = 1;
                        for (int k = 0; k < MAX_FD; k++) {
                            if (clients[k].client_fd == -1) {
                                clients[k].client_fd = client_fd;
                                clients[k].server_fd = sd->fd;
                                clients[k].last_seen = time(NULL);
                                break;
                            }
                        }
                    }

                    if (accept == 0) {
                        syslog(LOG_WARNING, "all fds are in use");
                        // fprintf(stderr, "error all fds are in use\n");
                        close(client_fd);
                        continue;
                    }
                }
                continue;
            }

            // check for event on client file descriptors
            struct client_data *client = NULL;
            for (int j = 0; j < MAX_FD; j++) {
                if (clients[j].client_fd == pfd.fd) {
                    client = &clients[j];
                    client->last_seen = time(NULL);
                    break;
                }
            }
            if (client == NULL) {
                // syslog(LOG_WARNING, "unknown file descriptor");
                fprintf(stderr, "unknown file descriptor\n");
                continue;
            }

            // look for associated socket
            for (int j = 0; j < data.sockets_len; j++) {
                if (data.sockets[j].fd == client->server_fd) {
                    sd = &data.sockets[j];
                }
            }
        
            int client_rv = client_handle(pfd);

            if (client_rv & CLIENT_PRINT) {
                print_data(pfd.fd, sd);
            }

            if (client_rv & CLIENT_FLUSH) {
                reset_data(sd);
            }

            // got or force disconnect
            if (client_rv & CLIENT_DISCONNECT) {                
                close(pfd.fd);

                fds[i].fd = -1;
                open_fd--;
                client->client_fd = -1;
                int negative_offset = open_fd - i;
                // closed file descriptor was not last in open -> move open fd down
                if (negative_offset) {
                    memmove(&fds[i], &fds[i+1], negative_offset * sizeof(struct pollfd));
                }
            }
        }
    }

    for (int i = 0; i < MAX_FD; i++) {
        if (clients[i].client_fd != -1) {
            close(clients[i].client_fd);
        }
    }

    if (!test_mode) {
        nflog_shutdown(&nh);
    }
    
    sockets_shutdown(&data);
    signal_shutdown(signal_fd);
    free_data(&data);

    exit(EXIT_SUCCESS);
}

int init_data(struct account_data *ad, char nets[][MAX_NET_LENGTH], int num_nets, char sockets[][MAX_SOCKETNAME_LENGTH], int num_sockets)
{
    char buf[INET_ADDRSTRLEN];
	struct in_addr addr;
    int i, j;
    u_int32_t net_mask_bits, net_mask;
    ad->nets = (struct net_data *)calloc(num_nets, sizeof(struct net_data));
    ad->nets_len = num_nets;

    for (i = 0; i < num_nets; i++) {
        char *net = nets[i];
        addr.s_addr = 0;
        for (j = 0; j < strlen(net); j++) {
            if (net[j] == '/') {
                if (j >= INET_ADDRSTRLEN) {
                    return -1;
                }
                strncpy(buf, net, j);
                buf[j] = 0;
                if (inet_pton(AF_INET, buf, &addr) != 1) {
                    return -1;
                }
                if (sscanf(&net[j + 1], "%u", &net_mask_bits) != 1) {
                    return -1;
                }
                if (net_mask_bits < 8 || net_mask_bits > 32) {
                    return -1;
                }
                break;
            }
        }

        if (addr.s_addr == 0) {
            return -1;
        }
        
        net_mask = 0;
        for (j = 0; j < net_mask_bits; j++) {
            net_mask ^= 1 << (31 -j);
        }
        // mask is in network byte order ... big endian ... highest first
        ad->nets[i].mask = htonl(net_mask);
        ad->nets[i].net = addr.s_addr & ad->nets[i].mask;
    }

    ad->sockets = (struct socket_data*)calloc(num_sockets, sizeof(struct socket_data));
    ad->sockets_len = num_sockets;
    for (i = 0; i < ad->sockets_len; i++) {
        struct socket_data *sd = &ad->sockets[i];
        // sd->hosts_len = sizeof(sd->hosts) / sizeof(* sd->hosts);
        sd->fd = -1;
        strlcpy(sd->name, sockets[i], MAX_SOCKETNAME_LENGTH);
        reset_data(sd);
    }
        
    return 0;
}

void reset_data(struct socket_data *sd)
{
    free(sd->hosts);
    sd->hosts = NULL;
    sd->hosts_len = 0;
    init_hosts(sd, HOST_BLOCK_SIZE);
}

void print_data(int fd, struct socket_data *sd)
{
    for (int i = 0; i < sd->hosts_len; i++) {
        if (sd->hosts[i].ip) {
            struct host_data *host = &sd->hosts[i];
            char addrbuf[INET_ADDRSTRLEN + 1] = {0};
            struct in_addr addr;
            addr.s_addr = host->ip;
            inet_ntop(AF_INET, &addr, addrbuf, sizeof(addrbuf));
            dprintf(fd, "%s %lu %lu %lu %lu %lu %lu\n", addrbuf, host->packets_src, host->bytes_src, host->packets_dst ,host->bytes_dst, host->first_seen, host->last_seen);
        }
    }		
}

void print_all_data(int fd, struct account_data *ad)
{
    for (int i = 0; i < ad->sockets_len; i++) {
        struct socket_data *sd = &ad->sockets[i];
        dprintf(fd, "%s\n", sd->name);
        print_data(fd, sd);
    }
}

void free_data(struct account_data *ad)
{
    if (ad->nets_len) {
        free(ad->nets);
    }
    if (ad->sockets_len) {
        for (int i = 0; i < ad->sockets_len; i++) {
            if (ad->sockets[i].hosts_len) {
                free(ad->sockets[i].hosts);
            }
        }
        free(ad->sockets);
    }
}

int nflog_init(struct nflog_handles *nh, int group, nflog_callback *cb, struct account_data *data)
{
    int fd;
    nh->h = nflog_open();
    if (!nh->h) {
        fprintf(stderr, "nflog_open\n");
        return -1;
    }

    int size = nfnl_rcvbufsiz(nflog_nfnlh(nh->h), NFLOG_BUFF_SIZE);
    if (size != NFLOG_BUFF_SIZE) {
        syslog(LOG_WARNING, "requested buffer size (%d) has not been set (%d)\n", NFLOG_BUFF_SIZE, size);
    }

    // printf("unbinding existing nf_log handler for AF_INET (if any)\n");
    // if (nflog_unbind_pf(nh->h, AF_INET) < 0) {
    //     fprintf(stderr, "error nflog_unbind_pf()\n");
    //     return -1;
    // }

    // if (nflog_bind_pf(nh->h, AF_INET) < 0) {
    //     fprintf(stderr, "nflog_bind_pf\n");
    //     return -1;
    // }

    nh->gh = nflog_bind_group(nh->h, group);
    if (!nh->gh) {
        fprintf(stderr, "no handle for group %d\n", group);
        return -1;
    }

    // copy 20 byte header only
    if (nflog_set_mode(nh->gh, NFULNL_COPY_PACKET, 20) < 0) {
        fprintf(stderr, "can't set packet copy mode\n");
        return -1;
    }

    if (nflog_set_flags(nh->gh, NFULNL_CFG_F_SEQ | NFULNL_CFG_F_SEQ_GLOBAL | NFULNL_CFG_F_CONNTRACK) < 0) {
        fprintf(stderr, "can't set flags\n");
        return -1;
    }

    fd = nflog_fd(nh->h);

    nflog_callback_register(nh->gh, cb, data);

    return fd;
}


void nflog_shutdown(struct nflog_handles *nh)
{
    nflog_unbind_group(nh->gh);
    nflog_close(nh->h);
}

int nflog_handle(struct pollfd pfd, struct nflog_handles *nh)
{

    if (pfd.revents & POLLHUP) {
        syslog(LOG_ERR, "nflog hangup");
        // fprintf(stderr, "nflog hangup\n");
        return -1;
    }
    
    int events = pfd.revents;

    if (pfd.revents & POLLERR) {
        syslog(LOG_WARNING, "nflog pollerr");
        // fprintf(stderr, "nflog pollerr\n");
        nflog_error_count++;
        if (nflog_error_count == 5) {
            syslog(LOG_ERR, "hit error count limit");
            // fprintf(stderr, "hit error count limit.\n");
            return -1;
        }
        events ^= POLLERR;
    }

    if (events & POLLIN) {
        if (nflog_error_count != 0) {
            nflog_error_count = 0;
        }

        int len = recv(pfd.fd, nflog_buffer, NFLOG_BUFF_SIZE, 0);
        
        if (len < 0) {
            syslog(LOG_WARNING, "error receiving from nflog (%d)", errno);
            // fprintf(stderr, "error receiving from nflog\n");
            if (errno == ENOBUFS) {
                syslog(LOG_INFO, "hit buffer limit");
            }
        } else {
            // fprintf(stdout, "received %d bytes\n", len);
            nflog_handle_packet(nh->h, nflog_buffer, len);
        }

        events ^= POLLIN;
    }

    if (events != 0) {
        syslog(LOG_NOTICE, "nflog unhandled events 0x%x", events);
        printf("nflog unhandled events 0x%x\n", events);
    }

    return 0;
}

static int nflog_cb(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg, struct nflog_data *nfa, void *data)
{
    char *payload;
    uint32_t seq, g_seq;
    time_t ts = time(NULL);
    struct net_data *net;

    nflog_get_seq(nfa, &seq);
    nflog_get_seq_global(nfa, &g_seq);

    int payload_len = nflog_get_payload(nfa, &payload);
    if (payload_len == -1) {
        syslog(LOG_ERR, "nflog_get_payload");
        return -1;
    }
    struct iphdr *ip = (struct iphdr *)payload;
	struct account_data *ad = (struct account_data *)data;
    
    int packet_size = htons(ip->tot_len);
    // if (packet_len != payload_len) {
    //     dprintf(STDOUT_FILENO, "packet size: %d, payload size: %d\n", packet_len, payload_len);
    // }
    

    for (int i = 0; i < ad->nets_len; i++) {
        net = &ad->nets[i];
        if ((ip->saddr & net->mask) == net->net) {
            for (int j = 0; j < ad->sockets_len; j++) {
                struct host_data *host = get_host(&ad->sockets[j], ip->saddr);
                host->packets_src++;
                host->bytes_src += packet_size;
                set_seen(host, ts);
            }
            break;
        }
        if ((ip->daddr & net->mask) == net->net) {
            for (int j = 0; j < ad->sockets_len; j++) {
                struct host_data *host = get_host(&ad->sockets[j], ip->daddr);
                host->packets_dst++;
                host->bytes_dst += packet_size;
                set_seen(host, ts);
            }
            break;
        }
    }

    if (ad->seq != seq) {
        syslog(LOG_WARNING, "error in sequence expected %d got %d\n", ad->seq, seq);
        ad->seq = seq;
    }

	ad->seq++;

    return 0;
}

void set_seen(struct host_data *host, time_t ts)
{
    if (host->first_seen == 0) {
        host->first_seen = ts;
    }
    host->last_seen = ts;
}

struct host_data* get_host(struct socket_data *sd, int addr)
{
    struct host_data *host = NULL;

    for (int i = 0; i < sd->hosts_len; i++) {
        if (sd->hosts[i].ip && sd->hosts[i].ip == addr) {
            host = &sd->hosts[i];
            break;
        }
    }

    if (host == NULL) {        
        for (int i = 0; i < sd->hosts_len; i++) {
            if (sd->hosts[i].ip == 0) {
                host = &sd->hosts[i];
                break;
            }
        }			
        if (host == NULL) {
            int offset = sd->hosts_len;
            init_hosts(sd, sd->hosts_len + HOST_BLOCK_SIZE);
            host = &sd->hosts[offset];
        }
        init_host(host, addr);
    }


    return host;
}

void init_host(struct host_data *host, int ip)
{
    host->ip = ip;
    host->packets_dst = 0;
    host->bytes_dst = 0;
    host->packets_src = 0;
    host->bytes_src = 0;
    host->first_seen = 0;
    host->last_seen = 0;
}

void init_hosts(struct socket_data *sd, int size)
{
    if (sd->hosts_len) {
        syslog(LOG_DEBUG, "resize %s hosts to %d", sd->name, size);
    }
    // alloc / realloc hosts array
    sd->hosts = reallocarray(sd->hosts, size, sizeof(struct host_data));
    // init newly allocated host structs
	for (int i = sd->hosts_len; i < size; i++) {
        init_host(&sd->hosts[i], 0);
	}
    // reflect new size
    sd->hosts_len = size;   
}

void sockets_shutdown(struct account_data *data)
{
    for (int i = 0; i < data->sockets_len; i++) {
        if (data->sockets[i].fd != -1) {
            socket_shutdown(data->sockets[i].fd, data->sockets[i].name);
        }
    }
}