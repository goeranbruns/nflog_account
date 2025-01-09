PROJECT = nflog_account
SOURCES = nflog_acct.c nla_signal.c nla_socket.c
CC = gcc
CFLAGS = -c -Wall
LDFLAGS = -lnetfilter_log -lnfnetlink

OBJECTS = $(SOURCES:.c=.o)
BINARY = $(PROJECT)

all: debug

executable: $(SOURCES) $(BINARY)

$(BINARY): $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@

distclean: clean
	rm -f $(BINARY)

clean:
	rm -f $(OBJECTS)

debug: CFLAGS += -g
debug: executable

release: CFLAGS += -O2
release: executable

# nflog_acct : $(objects)
# 				$(CC) $(CFLAGS) $(objects) $(LDLIBS) -o nflog_acct

# nflog_acct.o : nflog_acct.h nla_signal.h nla_socket.h

# nla_socket.o : nla_socket.h

# nla_signal.o : nla_signal.h

# .PHONY : clean
# clean :
# 		-rm nflog_acct $(objects)