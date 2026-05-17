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

.PHONY: all linux vet test release clean

all:
	go build -ldflags "$(LDFLAGS)" -o $(BIN) .

linux:
	mkdir -p dist
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BIN)-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BIN)-linux-arm64 .

vet:
	GOOS=linux go vet ./...

test:
	TRACEP=$(TRACEP) bash test/run.sh

# release: versioned linux binaries + RPMs (amd64/arm64) + checksums in dist/
release: linux
	cp dist/$(BIN)-linux-amd64 dist/tracep.staged
	VERSION=$(VERSION) NFPM_ARCH=amd64 nfpm package -f nfpm.yaml -p rpm -t dist/
	cp dist/$(BIN)-linux-arm64 dist/tracep.staged
	VERSION=$(VERSION) NFPM_ARCH=arm64 nfpm package -f nfpm.yaml -p rpm -t dist/
	rm -f dist/tracep.staged
	cd dist && shasum -a 256 $(BIN)-linux-* *.rpm > SHA256SUMS

clean:
	rm -rf $(BIN) dist
