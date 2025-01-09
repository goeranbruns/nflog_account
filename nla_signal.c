#include <signal.h>
#include <sys/signalfd.h>
#include <syslog.h>
#include <poll.h>
#include <stdio.h>
#include <unistd.h>
#include <bits/sigaction.h>

#include "nla_signal.h"

int signal_init()
{
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGHUP);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGTERM);
    sigaddset(&sigset, SIGPIPE);
    sigprocmask(SIG_BLOCK, &sigset, NULL);

    int fd = signalfd(-1, &sigset, 0);
    if (fd == -1) {
        fprintf(stderr, "signalfd");
        return -1;
    }

    return fd;
}

void signal_shutdown(int fd)
{
    close(fd);
}

int signal_handle(struct pollfd pfd)
{
    struct signalfd_siginfo fdsi;
    ssize_t s = sizeof(fdsi);
    int events = pfd.revents;

    if (events & POLLIN) {
        if (s != read(pfd.fd, &fdsi, s)) {
            syslog(LOG_WARNING, "error reading signal");
            // fprintf(stderr, "error reading signal\n");
            return -1;
        }
        if (fdsi.ssi_signo == SIGHUP) {
            return SIGNAL_PRINT;
        } else if (fdsi.ssi_signo == SIGINT || fdsi.ssi_signo == SIGKILL || fdsi.ssi_signo == SIGTERM) {
            return SIGNAL_SHUTDOWN;
        } else {
            syslog(LOG_NOTICE, "received unhandled signal (%d)", fdsi.ssi_signo);
            // fprintf(stderr, "received unhandled signal (%d)\n", fdsi.ssi_signo);
            return 0;
        }
        events ^= POLLIN;
    }

    if (events != 0) {
        syslog(LOG_NOTICE, "signal unhandled events 0x%x", events);
        // printf("signal unhandled events 0x%x\n", events);
    }

    return 0;
}
