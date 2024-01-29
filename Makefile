.PHONY: clean all static
CFLAGS = -Wall -g -O3
ARCH = $(shell uname -m)
VERSION = $(shell git describe | sed -e 's/-\([^-]*$$\)/+\1/')
CPPFLAGS = -DSYSLOG2STDOUT_VERSION='"$(VERSION)"'

all: syslog2stdout static

syslog2stdout: syslog2stdout.c

syslog2stdout-glibc.$(ARCH): syslog2stdout.c
	# "against libc6, with debug info and everything"
	/usr/bin/x86_64-linux-gnu-gcc $(LDFLAGS) $(CFLAGS) $(CPPFLAGS) -static -fdata-sections -ffunction-sections $< -o $@

syslog2stdout-musl.$(ARCH): syslog2stdout.c /usr/bin/x86_64-linux-musl-gcc
	# sudo apt-get install musl-dev
	/usr/bin/x86_64-linux-musl-gcc $(LDFLAGS) $(CFLAGS) $(CPPFLAGS) -static -fdata-sections -ffunction-sections $< -o $@ -Wl,--gc-sections -Wl,--strip-all

static: syslog2stdout-glibc.$(ARCH) syslog2stdout-musl.$(ARCH)
	@echo du:
	@echo '```'
	@du -bh syslog2stdout-*
	@echo '```'
	@echo sha256:
	@echo '```'
	@sha256sum syslog2stdout-*
	@echo '```'

clean:
	$(RM) syslog2stdout syslog2stdout-static syslog2stdout-musl
