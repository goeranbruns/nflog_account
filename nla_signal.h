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
#ifndef NLA_SIGNAL_H
#define NLA_SIGNAL_H

#define SIGNAL_PRINT    1
#define SIGNAL_SHUTDOWN 2

int signal_init();
void signal_shutdown(int);
int signal_handle(struct pollfd);

#endif