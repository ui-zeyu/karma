// Package trust states what a path is, structurally: whether it exists, what
// kind of object it is, who owns it, whether group or other can write it, and
// whether the package database carries it. A name never decides any of that.
//
// The package is a leaf: a caller hands it a path and, optionally, a Resolver
// for package ownership. The startup graph and the live watcher both use it, so
// a unit's ExecStart target and a process's exe are judged by the same facts.
package trust
