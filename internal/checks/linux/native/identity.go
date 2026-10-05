// native tiers of the identity checks: sudoers surfaces, sshd's
// AuthorizedKeysFile expansion, and the readFiles-backed config reads.

package native

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"karma/internal/localfs"
	"karma/internal/model"
)

// Sudoers mirrors the check's sudoersScript: every readable surface it hands
// in, one section each; none readable means this tier cannot answer and the
// sudo -n -l tier is next. A successful read is the script's [ -r ] guard: an
// unreadable file fails the read and is skipped.
func Sudoers(paths []string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		var b strings.Builder
		for _, path := range localfs.ExpandFiles(paths) {
			if body, err := os.ReadFile(path); err == nil {
				fmt.Fprintf(&b, "== %s\n", path)
				b.WriteString(string(body))
			}
		}
		if b.Len() == 0 {
			return "", model.ErrTierUnavailable
		}
		return b.String(), nil
	}
}

// expandHomes turns the check's home globs into the directories they name, the
// way the script's `for d in ...; do [ -d "$d" ] || continue` loop does, so an
// entry that names nothing contributes nothing either way.
func expandHomes(homeGlobs []string) []string {
	return localfs.ExpandGlobs(homeGlobs, func(info os.FileInfo) bool { return info.IsDir() })
}

// printBody appends one "== path" section with the file's best-effort body.
func printBody(b *strings.Builder, path string) {
	fmt.Fprintf(b, "== %s\n", path)
	if body, err := os.ReadFile(path); err == nil {
		b.WriteString(string(body))
	}
}

// AuthorizedKeys mirrors authorizedKeysScript: keys found by name under the home
// globs the check hands in, then the paths sshd_config's AuthorizedKeysFile
// directives name — %u the user, %h the home directory, a relative path inside
// it — skipping the default names the find already covered. depth is the same
// -maxdepth the script's find passes.
func AuthorizedKeys(homeGlobs []string, depth int, sshdConfigPaths []string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		homes := expandHomes(homeGlobs)
		var b strings.Builder
		printed := map[string]bool{}
		for _, home := range homes {
			_ = localfs.WalkTree(ctx, home, depth, false, nil, func(path string, info os.FileInfo) bool {
				if info.Mode().IsRegular() && strings.HasPrefix(filepath.Base(path), "authorized_keys") {
					if !printed[path] {
						printed[path] = true
						printBody(&b, path)
					}
				}
				return true
			})
		}
		for _, spec := range authorizedKeyFileSpecs(sshdConfigPaths) {
			switch spec {
			case "none", "authorized_keys", "authorized_keys2",
				".ssh/authorized_keys", ".ssh/authorized_keys2":
				continue
			}
			for _, home := range homes {
				path := strings.ReplaceAll(spec, "%u", filepath.Base(home))
				path = strings.ReplaceAll(path, "%h", home)
				path = strings.ReplaceAll(path, "%%", "%")
				if !strings.HasPrefix(path, "/") {
					path = filepath.Join(home, path)
				}
				if strings.HasSuffix(path, "/.ssh/authorized_keys") ||
					strings.HasSuffix(path, "/.ssh/authorized_keys2") || printed[path] {
					continue
				}
				if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
					printed[path] = true
					printBody(&b, path)
				}
			}
		}
		return b.String(), nil
	}
}

// authorizedKeyFileSpecs reads the AuthorizedKeysFile directives from the sshd
// config stack the check hands in: every word after the keyword, like the awk
// column pick.
func authorizedKeyFileSpecs(sshdConfigPaths []string) []string {
	var specs []string
	for _, path := range localfs.ExpandFiles(sshdConfigPaths) {
		body, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(body), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == "AuthorizedKeysFile" {
				specs = append(specs, fields[1:]...)
			}
		}
	}
	return specs
}
