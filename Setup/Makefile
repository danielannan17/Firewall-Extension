
CFLAGS = -D_POSIX_SOURCE -Wall -Werror -pedantic -std=c99 -D_GNU_SOURCE
GCC = gcc $(CFLAGS)


APPS = firewallSetup

all: $(APPS)

server: firewallSetup.c
	$(GCC) -o firewallSetup firewallSetup.c

clean:
	rm -f $(APPS) 