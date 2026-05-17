BIN := tracep
PKG := github.com/binRick/tracep

.PHONY: all linux clean vet

all:
	go build -o $(BIN) .

linux:
	mkdir -p dist
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/$(BIN)-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o dist/$(BIN)-linux-arm64 .

vet:
	GOOS=linux go vet ./...

clean:
	rm -rf $(BIN) dist
