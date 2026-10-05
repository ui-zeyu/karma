// native tiers of the identity checks: sudoers surfaces, sshd's
// AuthorizedKeysFile expansion, and the readFiles-backed config reads.

package linux

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"karma/internal/model"
)

// nativeSudoers mirrors sudoersScript: every readable sudoers surface, one
// section each; none readable means this tier cannot answer and the sudo -n -l
// tier is next. A successful read is the script's [ -r ] guard: an unreadable
// file fails the read and is skipped.
func nativeSudoers(ctx context.Context) (string, error) {
	var b strings.Builder
	for _, path := range expandFiles([]string{"/etc/sudoers", "/etc/sudo.conf", "/etc/sudoers.d/*"}) {
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

// homeDirs is /root plus every /home/* directory, in the glob order the
// scripts iterate.
func homeDirs() []string {
	var dirs []string
	for _, dir := range []string{"/root", "/home"} {
		if dir == "/home" {
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if entry.IsDir() {
					dirs = append(dirs, filepath.Join(dir, entry.Name()))
				}
			}
			continue
		}
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			dirs = append(dirs, dir)
		}
	}
	return dirs
}

// printBody appends one "== path" section with the file's best-effort body.
func printBody(b *strings.Builder, path string) {
	fmt.Fprintf(b, "== %s\n", path)
	if body, err := os.ReadFile(path); err == nil {
		b.WriteString(string(body))
	}
}

// nativeAuthorizedKeys mirrors authorizedKeysScript: keys found by name under
// home directories first, then the paths sshd_config's AuthorizedKeysFile
// directives name — %u the user, %h the home directory, a relative path inside
// it — skipping the default names the find already covered.
func nativeAuthorizedKeys(ctx context.Context) (string, error) {
	var b strings.Builder
	printed := map[string]bool{}
	for _, home := range homeDirs() {
		_ = walkTree(ctx, home, 3, false, nil, func(path string, info os.FileInfo) bool {
			if info.Mode().IsRegular() && strings.HasPrefix(filepath.Base(path), "authorized_keys") {
				if !printed[path] {
					printed[path] = true
					printBody(&b, path)
				}
			}
			return true
		})
	}
	for _, spec := range authorizedKeyFileSpecs() {
		switch spec {
		case "none", "authorized_keys", "authorized_keys2",
			".ssh/authorized_keys", ".ssh/authorized_keys2":
			continue
		}
		for _, home := range homeDirs() {
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

// authorizedKeyFileSpecs reads the AuthorizedKeysFile directives from sshd's
// own config stack: every word after the keyword, like the awk column pick.
func authorizedKeyFileSpecs() []string {
	var specs []string
	patterns := []string{"/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*.conf"}
	for _, path := range expandFiles(patterns) {
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
