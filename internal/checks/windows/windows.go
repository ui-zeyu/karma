// Package windows is the Windows check catalog: system information, accounts,
// processes, network, persistence, logs and other system surfaces, plus user
// behavior artifacts in the registry and user profiles.
//
// The artifact list and live-collection mapping come from the digest of HTB Academy module 248
// "User Behavior Forensics" and from common Chinese incident-response lists. All probes are one
// PowerShell argument vector (a few use native commands); a probe that answers with several parts
// declares one section title each, and a file list is read one call per path, so a section boundary
// is never a line in the output. Decoding (ROT-13, UTF-16 extraction, FILETIME, MRUListEx lists)
// happens locally in normalize.
//
// Design boundary: HKCU checks cover only the collecting identity's own user; other users' hives
// would need reg load (which writes system state), violating read-only, so it degrades to file
// globbing (an administrator can read all users).
package windows

import "slices"

// All lists every Windows check. The group order is the aspect order in the report: system surfaces
// first, user behavior after, logs and devices last.
var All = slices.Concat(
	SystemChecks,
	IdentityChecks,
	ProcessChecks,
	NetworkChecks,
	PersistenceChecks,
	ExecutionChecks,
	NavigationChecks,
	DocumentsChecks,
	RemoteChecks,
	WinLogChecks,
	TimelineChecks,
	DevicesChecks,
)
