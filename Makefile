.PHONY: clean all
CFLAGS = -Wall -O3

all: syslog2stdout syslog2stdout-static

syslog2stdout: syslog2stdout.c

syslog2stdout-static: syslog2stdout.c
	$(CC) $(LDFLAGS) $(CFLAGS) -static $< -o $@

clean:
	$(RM) syslog2stdout
