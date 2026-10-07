# Development gates and release binaries. The gates are the same set the tests
# run locally: gofmt lists nothing, vet and staticcheck report nothing, every
# test passes.

GO ?= go
VERSION ?= 0.37.1
.PHONY: all fmt vet test race staticcheck build linux-arm64 dist clean

all: fmt vet test

fmt:
	@unformatted=$$(gofmt -l .); if [ -n "$$unformatted" ]; then \
		echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi

vet:
	$(GO) vet ./...

test:
	$(GO) test -count=1 ./...

# The packages whose code runs across goroutines (presentation, channels,
# orchestration, the run's shared-read store, and the checks that publish and
# read that store from several workers) under the race detector.
race:
	$(GO) test -race -count=1 ./internal/render/ ./internal/session/ ./internal/runner/ ./internal/cli/ ./internal/runstate/ ./internal/checks/...

staticcheck:
	staticcheck -checks=all ./...

# Release binaries strip the symbol table and DWARF (-s -w) and drop local
# paths (-trimpath) to cut the transfer size; -X still stamps the version.
# CGO_ENABLED=0 keeps every binary statically linked: no dynamic loader means
# /etc/ld.so.preload cannot run code inside karma itself. The dist guard
# below refuses a release that regresses this.
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o dist/karma ./cmd/karma

# linux-arm64 cross-compiles the ARM64 Linux binary on its own. That is the PD
# lab's platform, and every ARM server (Graviton, Ampere, Kunpeng) — the one
# target whose host cannot build for itself here.
linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o dist/karma-linux-arm64 ./cmd/karma

# dist builds the release binaries for the two supported platforms, ARM64 Linux
# included.
dist: build linux-arm64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o dist/karma-linux-amd64 ./cmd/karma
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o dist/karma-windows-amd64.exe ./cmd/karma
	@file dist/karma-linux-amd64 | grep -q "statically linked" || { \
		echo "dist/karma-linux-amd64 is not statically linked"; exit 1; }
	@file dist/karma-linux-arm64 | grep -q "statically linked" || { \
		echo "dist/karma-linux-arm64 is not statically linked"; exit 1; }

clean:
	rm -rf dist
