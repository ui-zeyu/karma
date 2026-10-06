# Development gates and release binaries. The gates are the same set the tests
# run locally: gofmt lists nothing, vet and staticcheck report nothing, every
# test passes.

GO ?= go
VERSION ?= 0.33.1
# The practice target of `make parity`: a Linux host and, when sshd does not
# listen on 22, its port.
HOST ?=
PORT ?=
PARCH ?= amd64
# The checks the parity diff compares by default: these agree byte for byte.
# df, lsmod and mounts are deliberately left out — their two spellings differ in
# padding and in the kernel's own order, which is the recorded state of the
# remaining known differences, so a diff over them is noise; name them
# explicitly (SELECTORS="df lsmod mounts") to eyeball those rows.
SELECTORS ?= fstab accounts groups shadow

.PHONY: all fmt vet test race staticcheck build linux-arm64 dist parity clean

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

# Parity: one Linux host collected twice, once through the in-process tiers and
# once through the script tiers every remote channel runs (KARMA_NO_NATIVE makes
# the local channel skip each Dual's Run branch). --save writes each check's raw
# text, so a difference between the two bundles is the two spellings having
# drifted — or a check whose output is volatile between the runs, which is what
# SELECTORS is for. Both bundles stay in the target's /tmp for inspection.
#
#	make parity HOST=root@10.0.0.5
#	make parity HOST=root@10.0.0.5 PORT=32782 PARCH=arm64
parity:
	@test -n "$(HOST)" || { echo "make parity needs a Linux host: make parity HOST=user@host [PORT=n]"; exit 1; }
	@set -e; dir=$$(mktemp -d); trap 'rm -rf "$$dir"' EXIT; \
	 CGO_ENABLED=0 GOOS=linux GOARCH=$(PARCH) $(GO) build -trimpath -o "$$dir/karma" ./cmd/karma; \
	 scp -q $(if $(PORT),-P $(PORT),) "$$dir/karma" $(HOST):/tmp/karma-parity; \
	 { echo 'set -e'; \
	   echo 'chmod +x /tmp/karma-parity'; \
	   echo 'rm -rf /tmp/parity-native /tmp/parity-script'; \
	   echo '/tmp/karma-parity local $(SELECTORS) --save /tmp/parity-native >/dev/null'; \
	   echo 'KARMA_NO_NATIVE=1 /tmp/karma-parity local $(SELECTORS) --save /tmp/parity-script >/dev/null'; \
	   echo 'rm -f /tmp/karma-parity'; \
	   echo 'diff -r -x manifest.json /tmp/parity-native /tmp/parity-script'; \
	   echo 'echo "parity: the in-process and script tiers agree"'; \
	 } > "$$dir/remote.sh"; \
	 ssh $(if $(PORT),-p $(PORT),) $(HOST) 'sh -s' < "$$dir/remote.sh"

clean:
	rm -rf dist
