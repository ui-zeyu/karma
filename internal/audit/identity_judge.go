package audit

// Identity findings come from the relations, not from printing the files. An
// account that is uid 0 and in the docker group and has a NOPASSWD grant is
// one core problem; the chain names the independent root paths.

import (
	"fmt"
	"path/filepath"
	"strings"
)

func isLoginShell(shell string) bool {
	switch filepath.Base(shell) {
	case "bash", "sh", "dash", "zsh", "ksh", "fish":
		return true
	}
	return false
}

func passwordInPasswd(value string) bool {
	return value != "" && !passwordKinds[value]
}

func emptyPassword(account Account) bool {
	return account.ShadowKnown && !account.Locked && account.Shadow == ""
}

// accountGroups answers the groups an account belongs to: the supplementary
// members a group lists and the account's own primary GID, so the sudoers
// membership question and the privileged-group question agree.
func accountGroups(account Account, groups []Group) []Group {
	var out []Group
	seen := map[string]bool{}
	add := func(group Group) {
		if seen[group.Name] {
			return
		}
		seen[group.Name] = true
		out = append(out, group)
	}
	for _, group := range groups {
		for _, member := range group.Members {
			if member == account.Name {
				add(group)
				break
			}
		}
		if group.GID == account.GID {
			add(group)
		}
	}
	return out
}

func groupByName(name string, groups []Group) (Group, bool) {
	for _, group := range groups {
		if group.Name == name {
			return group, true
		}
	}
	return Group{}, false
}

// grantApplies answers whether a sudoers user/group expression reaches an
// account.
func grantApplies(grant SudoGrant, account Account, groups []Group) bool {
	if grant.User == "ALL" || grant.User == account.Name {
		return true
	}
	if name, ok := strings.CutPrefix(grant.User, "%"); ok {
		if _, found := groupByName(name, groups); !found {
			return false
		}
		for _, member := range accountGroups(account, groups) {
			if member.Name == name {
				return true
			}
		}
		if group, found := groupByName(name, groups); found && group.GID == account.GID {
			return true
		}
	}
	return false
}

type identityFactor struct {
	class    string
	text     string
	severity Severity
	path     string
	quotes   []Quote
}

// accountQuotes cites the passwd row an account was read from.
func accountQuotes(account Account) []Quote {
	if account.Raw == "" {
		return nil
	}
	return []Quote{{Path: account.Source, Line: account.Line, Text: account.Raw}}
}

// shadowQuotes cites the shadow row that answered for an account's password.
func shadowQuotes(account Account) []Quote {
	if account.ShadowRaw == "" {
		return nil
	}
	return []Quote{{Path: account.ShadowFile, Line: account.ShadowLine, Text: account.ShadowRaw}}
}

// groupQuotes cites the group row a membership was read from.
func groupQuotes(group Group) []Quote {
	if group.Raw == "" {
		return nil
	}
	return []Quote{{Path: group.Source, Line: group.Line, Text: group.Raw}}
}

// grantQuotes cites the sudoers row a grant was read from.
func grantQuotes(grant SudoGrant) []Quote {
	if grant.Raw == "" {
		return nil
	}
	return []Quote{{Path: grant.File, Line: grant.Line, Text: grant.Raw}}
}

// sshdQuotes cites the directive that redirected the authorized key search.
func sshdQuotes(config SSHDConfig) []Quote {
	if config.KeyRaw == "" {
		return nil
	}
	return []Quote{{Path: config.KeyFile, Line: config.KeyLine, Text: config.KeyRaw}}
}

// identityFactors collects the independent root paths on one account.
func identityFactors(account Account, groups []Group, grants []SudoGrant, keys []AuthorizedKeyCommand) []identityFactor {
	var factors []identityFactor
	if account.UID == 0 && account.Name != "root" {
		factors = append(factors, identityFactor{
			class: "identity-uid0", text: "non-root account with uid 0", severity: Critical, path: account.Source,
			quotes: accountQuotes(account),
		})
	}
	if emptyPassword(account) {
		severity := High
		if account.UID == 0 {
			severity = Critical
		}
		factors = append(factors, identityFactor{
			class: "identity-empty-password", text: "empty password", severity: severity, path: "/etc/shadow",
			quotes: shadowQuotes(account),
		})
	}
	if passwordInPasswd(account.Password) {
		factors = append(factors, identityFactor{
			class: "identity-password-in-passwd", text: "password hash or empty field in /etc/passwd",
			severity: High, path: account.Source,
		})
	}
	if account.System && account.Name != "root" && isLoginShell(account.Shell) {
		factors = append(factors, identityFactor{
			class: "identity-system-shell", text: "system account has a login shell", severity: Medium, path: account.Source,
			quotes: accountQuotes(account),
		})
	}
	for _, group := range accountGroups(account, groups) {
		severity, ok := privilegedGroups[group.Name]
		if !ok {
			continue
		}
		// A stock system account in adm/staff is normal (syslog reads logs);
		// the high-authority groups still count for every account.
		if account.System && severity <= Medium {
			continue
		}
		factors = append(factors, identityFactor{
			class: "identity-privileged-group", text: "member of privileged group " + group.Name,
			severity: severity, path: "/etc/group", quotes: groupQuotes(group),
		})
	}
	for _, grant := range grants {
		if grant.NoPasswd && grantApplies(grant, account, groups) {
			factors = append(factors, identityFactor{
				class: "identity-sudo-nopasswd", text: "passwordless sudo " + grant.Command,
				severity: High, path: grant.File, quotes: grantQuotes(grant),
			})
			break
		}
	}
	for _, key := range keys {
		if key.Account != account.Name {
			continue
		}
		severity := Medium
		if shellCommand(key.Command) {
			severity = High
		}
		class := "identity-key-command"
		if shellCommand(key.Command) {
			class = "identity-factor"
		}
		factors = append(factors, identityFactor{
			class: class, text: "authorized key forced command " + key.Command, severity: severity, path: key.File,
		})
		break
	}
	return factors
}

func shellCommand(command string) bool {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return false
	}
	name := strings.ToLower(filepath.Base(fields[0]))
	if shellInterpreters[name] || socketInterpreters[name] {
		return true
	}
	// A wrapper such as `sh -c` or `/bin/bash -c` is the same shape.
	for _, field := range fields {
		name = strings.ToLower(filepath.Base(field))
		if shellInterpreters[name] || socketInterpreters[name] {
			return true
		}
	}
	return false
}

// identitySeverity raises a factor one tier when its file arrived after the
// artifact: a runtime identity edit is at least critical, a modified one at
// least high, and a shipped one keeps the structural severity.
func identitySeverity(snapshot *Snapshot, a *assessor, factor identityFactor) Severity {
	if a == nil || factor.path == "" {
		return factor.severity
	}
	story := a.read(snapshot.Facts(factor.path), true)
	switch story.origin {
	case Runtime:
		if factor.severity < Critical {
			return Critical
		}
	case Modified:
		if factor.severity < High {
			return High
		}
	}
	return factor.severity
}

// judgeIdentity emits one correlated backdoor finding per account and the
// individual factors for accounts that carry only one. The artifact boundary
// applies here too: an identity file that arrived after the artifact raises
// the same factor a tier, so a planted sudoers row outranks a shipped one.
func judgeIdentity(snapshot *Snapshot, a *assessor, filter Filter, add func(Finding)) []string {
	state := &snapshot.Identity
	if len(state.Accounts) == 0 && len(state.Sudo) == 0 && len(state.SSHD.Files) == 0 {
		return nil
	}
	if len(filter.PIDs) > 0 || len(filter.Units) > 0 {
		return nil
	}
	var coverage []string
	correlated := map[string]bool{}
	for _, account := range state.Accounts {
		factors := identityFactors(account, state.Groups, state.Sudo, state.KeyCommands)
		if len(factors) < 2 {
			continue
		}
		for index := range factors {
			factors[index].severity = identitySeverity(snapshot, a, factors[index])
		}
		severity := High
		trace := []Step{{Text: "account " + account.Name, Node: nodeKey("account", account.Name)}}
		var evidence []string
		for _, factor := range factors {
			trace = append(trace, Step{Text: factor.text})
			evidence = append(evidence, factor.text)
			if factor.severity > severity {
				severity = factor.severity
			}
		}
		if !pathInScope("/etc/passwd", filter) && !pathInScope("/etc/shadow", filter) {
			continue
		}
		correlated[account.Name] = true
		add(Finding{
			Class: "identity-backdoor", Severity: severity,
			Title: "account holds multiple independent authority paths",
			Path:  "/etc/passwd", Origin: Unknown, Reach: RootAsset,
			Detail:   fmt.Sprintf("account %s: %d independent root paths", account.Name, len(factors)),
			Evidence: evidence, Quotes: accountQuotes(account), Trace: trace,
		})
	}
	for _, account := range state.Accounts {
		if correlated[account.Name] {
			continue
		}
		for _, factor := range identityFactors(account, state.Groups, state.Sudo, state.KeyCommands) {
			if !pathInScope(factor.path, filter) {
				continue
			}
			add(Finding{
				Class: factor.class, Severity: identitySeverity(snapshot, a, factor),
				Title: factor.text, Path: factor.path, Origin: Unknown, Reach: RootAsset,
				Detail: fmt.Sprintf("account %s", account.Name),
				Quotes: factor.quotes, Trace: steps("account "+account.Name, factor.text),
			})
		}
	}
	seenGrants := map[string]bool{}
	for _, grant := range state.Sudo {
		if !grant.NoPasswd {
			continue
		}
		if correlated[grant.User] {
			continue
		}
		if !pathInScope(grant.File, filter) {
			continue
		}
		key := fmt.Sprintf("%s:%d:%s:%s", grant.File, grant.Line, grant.User, grant.Command)
		if seenGrants[key] {
			continue
		}
		seenGrants[key] = true
		add(Finding{
			Class: "identity-sudo-nopasswd", Severity: identitySeverity(snapshot, a, identityFactor{
				class: "identity-sudo-nopasswd", severity: High, path: grant.File,
			}),
			Title: "passwordless sudo grant", Path: grant.File, Origin: Unknown, Reach: RootAsset,
			Detail:   fmt.Sprintf("%s may run %s without a password", grant.User, grant.Command),
			Evidence: []string{fmt.Sprintf("%s:%d host %s runas %s", grant.File, grant.Line, grant.Host, grant.RunAs)},
			Quotes:   grantQuotes(grant),
			Trace:    steps("sudoers "+grant.File, "grant "+grant.User, "command "+grant.Command),
		})
	}
	coverage = append(coverage, judgeSSHD(state, filter, add)...)
	if !pathInScope("/etc/group", filter) {
		return coverage
	}
	for _, group := range state.Groups {
		if group.Password != "" && !passwordKinds[group.Password] {
			add(Finding{
				Class: "identity-group-password", Severity: Medium,
				Title: "group password set", Path: group.Source, Origin: Unknown, Reach: RootAsset,
				Detail:   fmt.Sprintf("group %s can be entered with newgrp", group.Name),
				Evidence: []string{"the group password field is not x, * or !"},
				Quotes:   groupQuotes(group),
				Trace:    steps("group "+group.Name, "password set"),
			})
		}
	}
	return coverage
}

func judgeSSHD(state *IdentityState, filter Filter, add func(Finding)) []string {
	var coverage []string
	if len(state.SSHD.Files) == 0 {
		return coverage
	}
	sshPath := state.SSHD.Files[0]
	if !pathInScope(sshPath, filter) {
		return coverage
	}
	defaultKeys := map[string]bool{
		".ssh/authorized_keys": true, ".ssh/authorized_keys2": true,
		"authorized_keys": true, "authorized_keys2": true, "none": true,
	}
	for _, value := range state.SSHD.AuthorizedKeysFile {
		if defaultKeys[value] {
			continue
		}
		add(Finding{
			Class: "identity-sshd-keyfile", Severity: High,
			Title: "sshd reads authorized keys from a non-default path",
			Path:  sshPath, Origin: Unknown, Reach: RootAsset,
			Detail:   "a redirected key file is a key-based backdoor surface",
			Evidence: []string{"AuthorizedKeysFile " + strings.Join(state.SSHD.AuthorizedKeysFile, " ")},
			Quotes:   sshdQuotes(state.SSHD),
			Trace:    steps("sshd_config", "AuthorizedKeysFile", value),
		})
		break
	}
	return coverage
}

func identityGraph(snapshot *Snapshot) *GraphView {
	root := NewGraphBuilder(&GraphNode{
		ID: nodeKey("domain", "identity"), Kind: "domain", Name: "identity",
		Origin: Unknown.String(), Detail: "accounts, groups, sudo grants, shadow state and SSH keys",
	})
	for _, group := range snapshot.Identity.Groups {
		root.Node("group", group.Name, group.Name, group.Source, Unknown, UserAsset,
			fmt.Sprintf("gid %d members %d", group.GID, len(group.Members)))
	}
	for _, account := range snapshot.Identity.Accounts {
		reach := UserAsset
		if account.UID == 0 {
			reach = RootAsset
		}
		node := root.Node("account", account.Name, account.Name, account.Source, Unknown, reach,
			fmt.Sprintf("uid %d gid %d home %s shell %s", account.UID, account.GID, account.Home, account.Shell))
		root.link(root.root, node.ID, "contains", "identity", "high", "")
		for _, group := range accountGroups(account, snapshot.Identity.Groups) {
			id := nodeKey("group", group.Name)
			root.link(node.ID, id, "member-of", "group", "high", "")
		}
		state := "shadow hash set"
		if account.Locked {
			state = "shadow locked"
		} else if emptyPassword(account) {
			state = "shadow empty"
		}
		s := root.Node("secret", "shadow:"+account.Name, "shadow", "/etc/shadow", Unknown, reach, state)
		root.link(node.ID, s.ID, "password", "shadow", "high", "")
		for _, key := range snapshot.Identity.KeyCommands {
			if key.Account != account.Name {
				continue
			}
			k := root.Node("key", key.Command, key.Command, key.File, Unknown, reach, "forced command")
			root.link(node.ID, k.ID, "authorized-by", "authorized_keys", "high", "")
		}
		for _, grant := range snapshot.Identity.Sudo {
			if !grantApplies(grant, account, snapshot.Identity.Groups) {
				continue
			}
			label := fmt.Sprintf("%s:%d %s → %s", grant.File, grant.Line, grant.User, grant.Command)
			if grant.NoPasswd {
				label += " (NOPASSWD)"
			}
			g := root.Node("grant", label, label, grant.File, Unknown, RootAsset, "sudo grant")
			root.link(node.ID, g.ID, "granted", "sudoers", "high", fmt.Sprintf("%s:%d", grant.File, grant.Line))
		}
	}
	if len(snapshot.Identity.SSHD.Files) > 0 {
		ssh := root.Node("config", "sshd_config", "sshd_config", snapshot.Identity.SSHD.Files[0], Unknown, RootAsset,
			fmt.Sprintf("AuthorizedKeysFile %s · PermitRootLogin %s · PasswordAuthentication %s",
				strings.Join(snapshot.Identity.SSHD.AuthorizedKeysFile, " "),
				valueOr(snapshot.Identity.SSHD.PermitRootLogin, "default"),
				valueOr(snapshot.Identity.SSHD.PasswordAuthentication, "default")))
		root.link(root.root, ssh.ID, "contains", "sshd", "high", "")
	}
	return root.GraphView("domain", snapshot)
}
