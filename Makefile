.PHONY: clean all static-builds
CFLAGS = -Wall -g -O3
LDFLAGS =
ARCH = $(shell uname -m)
VERSION = $(shell git describe | sed -e 's/-\([^-]*$$\)/+\1/')
CPPFLAGS = -DSYSLOG2STDOUT_VERSION='"$(VERSION)"'
APP_STATIC = syslog2stdout-glibc.$(ARCH) syslog2stdout-musl.$(ARCH)

all: syslog2stdout static-builds

syslog2stdout: syslog2stdout.c
	# see 'make -p' for defaults (LINK.c + ...)
	ccver=$$($(CC) --version | sed -e '1!d') && \
	$(CC) $(CFLAGS) $(CPPFLAGS) -DCOMPILER_VERSION='"'"$$ccver"'"' \
	  $(LDFLAGS) $(TARGET_ARCH) $^ $(LDLIBS) -o $@

syslog2stdout-glibc.$(ARCH): syslog2stdout.c
	# "against libc6, with debug info and everything"
	ccver=$$(/usr/bin/x86_64-linux-gnu-gcc --version | sed -e '1!d') && \
	/usr/bin/x86_64-linux-gnu-gcc $(CFLAGS) \
	  -fdata-sections -ffunction-sections \
	  $(CPPFLAGS) -DCOMPILER_VERSION='"'"$$ccver"'"' $(LDFLAGS) -static \
	  $(TARGET_ARCH) $^ $(LDLIBS) -o $@

syslog2stdout-musl.$(ARCH): syslog2stdout.c
	# sudo apt-get install musl-dev
	ccver=$$(/usr/bin/x86_64-linux-musl-gcc --version | sed -e '1!d') && \
	/usr/bin/x86_64-linux-musl-gcc $(CFLAGS) \
	  -fdata-sections -ffunction-sections \
	  $(CPPFLAGS) -DCOMPILER_VERSION='"'"$$ccver"'"' $(LDFLAGS) -static \
	  -Wl,--gc-sections -Wl,--strip-all \
	  $(TARGET_ARCH) $^ $(LDLIBS) -o $@

static-builds: syslog2stdout-glibc.$(ARCH) syslog2stdout-musl.$(ARCH)
	@echo du:
	@echo '```'
	@du -bh syslog2stdout-*
	@echo '```'
	@echo sha256:
	@echo '```'
	@sha256sum syslog2stdout-*
	@echo '```'
	@echo versions:
	@echo '```'
	@for app in $^; do echo "$$(./$$app 2>&1 | head -n1)  $$app"; done
	@echo '```'

clean:
	$(RM) syslog2stdout $(APP_STATIC)
