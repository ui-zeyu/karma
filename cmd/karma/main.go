// karma's entry point; the version can be overridden at build time with
// -ldflags "-X main.version=…".
package main

import (
	"os"

	"karma/internal/cli"
)

// version is the release version, overridable by the build.
var version = "0.39.0"

func main() {
	os.Exit(cli.Main(version))
}
