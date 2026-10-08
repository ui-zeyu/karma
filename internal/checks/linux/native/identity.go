// native tiers of the identity checks: sudoers surfaces, sshd's
// AuthorizedKeysFile expansion, and the readFiles-backed config reads.

package native

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"karma/internal/localfs"
	"karma/internal/model"
)

// SudoersFiles lists the readable surfaces it hands in; none readable means this
// tier cannot answer and the sudo -n -l tier is next. An unreadable file is left
// out of the list, which is what a [ -r ] guard would do.
func SudoersFiles(paths []string) func(context.Context) (string, error) {
	return func(context.Context) (string, error) {
		var readable []string
		for _, path := range localfs.ExpandFiles(paths) {
			if _, err := localfs.ReadRegular(path); err == nil {
				readable = append(readable, path)
			}
		}
		if len(readable) == 0 {
			return "", model.ErrTierUnavailable
		}
		return strings.Join(readable, "\n"), nil
	}
}

// expandHomes turns the check's home globs into the directories they name, so an
// entry that names nothing contributes nothing.
func expandHomes(homeGlobs []string) []string {
	return localfs.ExpandGlobs(homeGlobs, func(info os.FileInfo) bool { return info.IsDir() })
}

// AuthorizedKeyFiles lists the key files: the ones found by name under the home
// globs the check hands in, then the paths sshd_config's AuthorizedKeysFile
// directives name — %u the user, %h the home directory, a relative path inside
// it — skipping the default names the walk already covered. depth bounds the
// walk under each home. The files themselves are read one call each, so a FIFO
// planted at a path the directive names cannot hang the tier: the read is
// localfs's non-blocking one.
func AuthorizedKeyFiles(homeGlobs []string, depth int, sshdConfigPaths []string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		homes := expandHomes(homeGlobs)
		var files []string
		printed := map[string]bool{}
		add := func(path string) {
			if !printed[path] {
				printed[path] = true
				files = append(files, path)
			}
		}
		for _, home := range homes {
			_ = localfs.WalkTree(ctx, home, depth, false, nil, func(path string, info os.FileInfo) bool {
				if info.Mode().IsRegular() && strings.HasPrefix(filepath.Base(path), "authorized_keys") {
					add(path)
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
					add(path)
				}
			}
		}
		return strings.Join(files, "\n"), nil
	}
}

// authorizedKeyFileSpecs reads the AuthorizedKeysFile directives from the sshd
// config stack the check hands in: every word after the keyword, like the awk
// column pick.
func authorizedKeyFileSpecs(sshdConfigPaths []string) []string {
	var specs []string
	for _, path := range localfs.ExpandFiles(sshdConfigPaths) {
		// ReadRegular rather than os.ReadFile: the config stack is host-writable,
		// and a planted FIFO must read as an empty config instead of parking the
		// tier in open(2) (localfs owns that guarantee).
		body, err := localfs.ReadRegular(path)
		if err != nil {
			continue
		}
		for line := range strings.SplitSeq(string(body), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == "AuthorizedKeysFile" {
				specs = append(specs, fields[1:]...)
			}
		}
	}
	return specs
}
