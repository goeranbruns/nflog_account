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
