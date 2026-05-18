BIN     := tracep
PKG     := github.com/binRick/tracep
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# Stamp the version into main and every subpackage banner.
LDFLAGS := -s -w \
  -X main.version=$(VERSION) \
  -X $(PKG)/internal/nettrace.version=$(VERSION) \
  -X $(PKG)/internal/tlstrace.version=$(VERSION) \
  -X $(PKG)/internal/dnstrace.version=$(VERSION) \
  -X $(PKG)/internal/exectrace.version=$(VERSION) \
  -X $(PKG)/internal/cafetch.version=$(VERSION)

# Two implementations share this Makefile:
#   make        Go binary  -> ./tracep            (default)
#   make c      C  binary  -> ./c/tracep
#   make all    both
#   make test   bash suite vs each built binary
# Go cross-compile / release targets are Go-only and unchanged.
.DEFAULT_GOAL := go
.PHONY: go c all linux darwin vet unit test test-go test-c release clean

go:
	go build -ldflags "$(LDFLAGS)" -o $(BIN) .

c:
	$(MAKE) -C c VERSION=$(VERSION)

all: go c

linux:
	mkdir -p dist
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BIN)-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BIN)-linux-arm64 .

# macOS binaries: `ca` + `dns` (BPF) work natively; net/tls/exec print a
# clear Linux-only message.
darwin:
	mkdir -p dist
	GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BIN)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BIN)-darwin-arm64 .

vet:
	GOOS=linux  go vet ./...
	GOOS=darwin go vet ./...

unit:
	go test ./...

# Run the black-box suite against each build. Override one with
# `make test-go` / `make test-c`, or point at an existing binary via
# `make test TRACEP=/path/to/tracep` (single run, back-compat).
test:
ifneq ($(TRACEP),)
	TRACEP=$(TRACEP) bash test/run.sh
else
	$(MAKE) test-go
	$(MAKE) test-c
endif

test-go: go
	@echo "── suite vs Go (./$(BIN)) ──"
	TRACEP=$(CURDIR)/$(BIN) bash test/run.sh

test-c: c
	@echo "── suite vs C (./c/$(BIN)) ──"
	TRACEP=$(CURDIR)/c/$(BIN) bash test/run.sh

# release: versioned linux+darwin binaries + RPMs (amd64/arm64) + checksums
release: linux darwin
	cp dist/$(BIN)-linux-amd64 dist/tracep.staged
	VERSION=$(VERSION) NFPM_ARCH=amd64 nfpm package -f nfpm.yaml -p rpm -t dist/
	cp dist/$(BIN)-linux-arm64 dist/tracep.staged
	VERSION=$(VERSION) NFPM_ARCH=arm64 nfpm package -f nfpm.yaml -p rpm -t dist/
	rm -f dist/tracep.staged
	cd dist && shasum -a 256 $(BIN)-linux-* $(BIN)-darwin-* *.rpm > SHA256SUMS

clean:
	rm -rf $(BIN) dist
	$(MAKE) -C c clean
