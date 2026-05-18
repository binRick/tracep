# C port of tracep — one self-contained binary, mirroring the Go build.
#
#   make            build ./tracep for the host
#   make clean
#
# Linux: all five tracers build natively. macOS: ca + dns build natively;
# net/tls/exec compile to a Linux-only stub (same gating as the Go //go:build
# tags). `ca` links OpenSSL (libssl/libcrypto) — the one external dependency
# the Go stdlib made unnecessary; everything else is libc only.

CC      ?= cc
VERSION ?= dev
CFLAGS  ?= -O2 -Wall -Wextra -std=c11
CFLAGS  += -DTRACEP_VERSION='"$(VERSION)"'
# net.c uses detached pthreads for async reverse DNS + CMD-mode child wait.
LDFLAGS += -pthread

BIN  = tracep
SRC  = tracep.c common.c dns.c net.c tls.c exec.c ca.c
HDR  = common.h

UNAME := $(shell uname -s)

# OpenSSL discovery (for ca.c). Prefer pkg-config; fall back to Homebrew
# on macOS, then to plain -lssl -lcrypto.
PKG_SSL := $(shell pkg-config --exists openssl 2>/dev/null && echo yes)
ifeq ($(PKG_SSL),yes)
  SSL_CFLAGS := $(shell pkg-config --cflags openssl)
  SSL_LIBS   := $(shell pkg-config --libs openssl)
else ifeq ($(UNAME),Darwin)
  BREW_SSL := $(shell brew --prefix openssl@3 2>/dev/null || brew --prefix openssl 2>/dev/null)
  SSL_CFLAGS := -I$(BREW_SSL)/include
  SSL_LIBS   := -L$(BREW_SSL)/lib -lssl -lcrypto
else
  SSL_CFLAGS :=
  SSL_LIBS   := -lssl -lcrypto
endif

$(BIN): $(SRC) $(HDR)
	$(CC) $(CFLAGS) $(SSL_CFLAGS) -o $@ $(SRC) $(LDFLAGS) $(SSL_LIBS)

clean:
	rm -f $(BIN)

.PHONY: clean
