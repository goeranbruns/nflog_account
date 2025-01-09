#ifndef NLA_SOCKET_H
#define NLA_SOCKET_H

#define CLIENT_PRINT 1
#define CLIENT_DISCONNECT 2
#define CLIENT_FLUSH 4

#define CLIENT_CMD_FLUSH "flush"
#define CLIENT_CMD_STATS "stats"

int socket_init(char *);
void socket_shutdown(int, char*);
int socket_handle(struct pollfd);
int client_handle(struct pollfd);

#endif