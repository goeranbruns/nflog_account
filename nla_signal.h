#ifndef NLA_SIGNAL_H
#define NLA_SIGNAL_H

#define SIGNAL_PRINT    1
#define SIGNAL_SHUTDOWN 2

int signal_init();
void signal_shutdown(int);
int signal_handle(struct pollfd);

#endif