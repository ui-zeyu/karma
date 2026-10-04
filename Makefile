# Development gates and release binaries. The gates are the same set the tests
# run locally: gofmt lists nothing, vet and staticcheck report nothing, every
# test passes.

GO ?= go
VERSION ?= 0.4.0

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
# orchestration) under the race detector.
race:
	$(GO) test -race -count=1 ./internal/render/ ./internal/session/ ./internal/runner/ ./internal/cli/

staticcheck:
	staticcheck -checks=all ./...

build:
	$(GO) build -ldflags "-X main.version=$(VERSION)" -o dist/karma ./cmd/karma

# dist builds the release binaries for the two supported platforms.
dist: build
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags "-X main.version=$(VERSION)" -o dist/karma-linux-amd64 ./cmd/karma
	GOOS=windows GOARCH=amd64 $(GO) build -ldflags "-X main.version=$(VERSION)" -o dist/karma-windows-amd64.exe ./cmd/karma

clean:
	rm -rf dist
