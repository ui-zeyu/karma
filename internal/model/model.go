// Package model defines the domain objects: platform, aspect, severity,
// invocation, probe, check, rule, and reading results. Every type depends on
// the standard library only; the check catalog is built in package-level
// variables and stays read-only at runtime.
package model

import (
	"slices"
)

// Platform is the target platform. The second catalog besides Linux is
// Windows user-behavior forensics.
type Platform string

const (
	Linux   Platform = "linux"
	Windows Platform = "windows"
)

// platformOrder is the declaration order of all platforms: the same single
// source as aspectOrder, used for grouping and as the selector vocabulary (a
// platform name selects every check of that platform).
var platformOrder = []Platform{Linux, Windows}

// Aspect is the group a check belongs to; it sets the grouping and order in
// the report.
type Aspect string

const (
	AspectSystem      Aspect = "system"
	AspectIdentity    Aspect = "identity"
	AspectProcess     Aspect = "process"
	AspectNetwork     Aspect = "network"
	AspectService     Aspect = "service"
	AspectPersistence Aspect = "persistence"
	AspectFilesystem  Aspect = "filesystem"
	AspectLog         Aspect = "log"
	AspectKernel      Aspect = "kernel"
	AspectPackage     Aspect = "package"
	AspectExecution   Aspect = "execution"
	AspectDocuments   Aspect = "documents"
	AspectNavigation  Aspect = "navigation"
	AspectRemote      Aspect = "remote"
	AspectDevices     Aspect = "devices"
	AspectTimeline    Aspect = "timeline"
)

// aspectOrder is the declaration order of all aspects; both the catalog
// grouping and the selector vocabulary come from it.
var aspectOrder = []Aspect{
	AspectSystem, AspectIdentity, AspectProcess, AspectNetwork, AspectService,
	AspectPersistence, AspectFilesystem, AspectLog, AspectKernel, AspectPackage,
	AspectExecution, AspectDocuments, AspectNavigation, AspectRemote,
	AspectDevices, AspectTimeline,
}

// Syntax is the presentation layer's lexer declaration for a check's body
// lines: the pseudo-lexer, or the chroma lexer, that colors its rows. It is a
// vocabulary like Aspect, so a catalog names one only through the constants
// below and a misspelling is a compile error rather than a panel that silently
// loses its color. The empty syntax declares none; the presentation layer's
// lexer table is checked against every syntax the catalog declares.
type Syntax string

const (
	SyntaxLsL        Syntax = "ls-l"
	SyntaxEnv        Syntax = "env"
	SyntaxDmesg      Syntax = "dmesg"
	SyntaxSshdConfig Syntax = "sshd-config"
	SyntaxSSHPubkey  Syntax = "ssh-pubkey"
	SyntaxColon      Syntax = "colon"
	SyntaxLsmod      Syntax = "lsmod"
	SyntaxIPAddr     Syntax = "ip-addr"
	SyntaxTable      Syntax = "table"
	SyntaxTree       Syntax = "tree"
	SyntaxFree       Syntax = "free"
	SyntaxLast       Syntax = "last"
	SyntaxLastlog    Syntax = "lastlog"
	SyntaxUnits      Syntax = "units"
	SyntaxUnitFiles  Syntax = "unit-files"
	SyntaxTimers     Syntax = "timers"
	SyntaxListen     Syntax = "listen"
	SyntaxNetstat    Syntax = "netstat"
	SyntaxPkgHistory Syntax = "pkg-history"
	SyntaxReg        Syntax = "reg"
	SyntaxPipe       Syntax = "pipe"
	SyntaxPowerShell Syntax = "powershell"
	SyntaxBash       Syntax = "bash"
)

// enumNames and enumByName turn an enum's declaration order into its name list
// and its name lookup: every vocabulary in this package comes from one of them,
// so the report grouping and the selector accept the same words.
func enumNames[T ~string](values []T) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	return out
}

func enumByName[T ~string](values []T) map[string]T {
	out := make(map[string]T, len(values))
	for _, value := range values {
		out[string(value)] = value
	}
	return out
}

var (
	aspectNames     = enumNames(aspectOrder)
	aspectsByName   = enumByName(aspectOrder)
	platformNames   = enumNames(platformOrder)
	platformsByName = enumByName(platformOrder)
)

// AspectNames returns every aspect name in declaration order.
func AspectNames() []string { return slices.Clone(aspectNames) }

// AspectByName resolves an aspect name; ok is false for an unknown name.
func AspectByName(name string) (Aspect, bool) {
	aspect, ok := aspectsByName[name]
	return aspect, ok
}

// PlatformNames returns every platform name in declaration order.
func PlatformNames() []string { return slices.Clone(platformNames) }

// PlatformByName resolves a platform name; ok is false for an unknown name.
func PlatformByName(name string) (Platform, bool) {
	platform, ok := platformsByName[name]
	return platform, ok
}
