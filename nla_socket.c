#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <poll.h>
#include <syslog.h>

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

void socket_shutdown(int fd, char* name)
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

int client_handle(struct pollfd pfd)
{
    int events = pfd.revents;
    int rv = 0;

    if (events & POLLIN) {
        char buf[32];
        int ret = read(pfd.fd, buf, sizeof(buf));
        if (ret == -1) {
            syslog(LOG_WARNING, "error read from client");
            // fprintf(stderr, "error read from client\n");
        } else {
            buf[sizeof(buf) - 1] = 0;
            
            // printf("received \"%s\"\n", buf);
            
            if (strncmp(CLIENT_CMD_STATS, buf, 5) == 0) {
                rv = CLIENT_PRINT | CLIENT_DISCONNECT;
            } else if (strncmp(CLIENT_CMD_FLUSH, buf, 5) == 0) {
                rv = CLIENT_PRINT | CLIENT_FLUSH | CLIENT_DISCONNECT;
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