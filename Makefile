# Development gates and release binaries. The gates are the same set the tests
# run locally: gofmt lists nothing, vet and staticcheck report nothing, every
# test passes.

GO ?= go
VERSION ?= 0.25.0

.PHONY: all fmt vet test race staticcheck build dist clean

all: fmt vet test

fmt:
	@unformatted=$$(gofmt -l .); if [ -n "$$unformatted" ]; then \
		echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi

vet:
	$(GO) vet ./...

test:
	$(GO) test -count=1 ./...

# The packages whose code runs across goroutines (presentation, channels,
# orchestration, and the run's shared-read store) under the race detector.
race:
	$(GO) test -race -count=1 ./internal/render/ ./internal/session/ ./internal/runner/ ./internal/cli/ ./internal/runstate/

staticcheck:
	staticcheck -checks=all ./...

# Release binaries strip the symbol table and DWARF (-s -w) and drop local
# paths (-trimpath) to cut the transfer size; -X still stamps the version.
# CGO_ENABLED=0 keeps every binary statically linked: no dynamic loader means
# /etc/ld.so.preload cannot run code inside karma itself. The dist guard
# below refuses a release that regresses this.
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o dist/karma ./cmd/karma

# dist builds the release binaries for the two supported platforms.
dist: build
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o dist/karma-linux-amd64 ./cmd/karma
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o dist/karma-windows-amd64.exe ./cmd/karma
	@file dist/karma-linux-amd64 | grep -q "statically linked" || { \
		echo "dist/karma-linux-amd64 is not statically linked"; exit 1; }

clean:
	rm -rf dist
