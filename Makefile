.PHONY: clean all
CFLAGS = -Wall -g -O3

all: syslog2stdout syslog2stdout-static syslog2stdout-musl

syslog2stdout: syslog2stdout.c

syslog2stdout-static: syslog2stdout.c
	# "against libc6, with debug info and everything"
	$(CC) $(LDFLAGS) $(CFLAGS) -static -fdata-sections -ffunction-sections $< -o $@

syslog2stdout-musl: syslog2stdout.c /usr/bin/x86_64-linux-musl-gcc
	# sudo apt-get install musl-dev
	/usr/bin/x86_64-linux-musl-gcc $(LDFLAGS) $(CFLAGS) -static -fdata-sections -ffunction-sections $< -o $@ -Wl,--gc-sections -Wl,--strip-all

clean:
	$(RM) syslog2stdout syslog2stdout-static syslog2stdout-musl
