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

// grantApplies answers whether a sudoers user/group expression reaches an
// account. The membership comes from the identity state's own index, so a
// caller cannot hand it the whole host's group table.
func grantApplies(grant SudoGrant, state *IdentityState, account Account) bool {
	if grant.User == "ALL" || grant.User == account.Name {
		return true
	}
	if name, ok := strings.CutPrefix(grant.User, "%"); ok {
		for _, group := range state.groupsFor(account) {
			if group.Name == name {
				return true
			}
		}
	}
	return false
}

type identityFactor struct {
	class    Class
	text     string
	severity Severity
	path     string
	quotes   []Quote
}

// accountQuotes cites the passwd row an account was read from.
// cite quotes one source line for a finding; an empty line quotes nothing.
// Every citation in the identity and persistence judges goes through here,
// so a quote's shape has one constructor.
func cite(path string, line int, text string) []Quote {
	if text == "" {
		return nil
	}
	return []Quote{{Path: path, Line: line, Text: text}}
}

// identityFactors collects the independent root paths on one account. The
// state's group index answers membership; grants are read against the
// account's own groups, computed once here.
func identityFactors(state *IdentityState, account Account) []identityFactor {
	groups := state.groupsFor(account)
	var factors []identityFactor
	if account.UID == 0 && account.Name != "root" {
		factors = append(factors, identityFactor{
			class: "identity-uid0", text: "non-root account with uid 0", severity: Critical, path: account.Source,
			quotes: cite(account.Source, account.Line, account.Raw),
		})
	}
	if emptyPassword(account) {
		severity := High
		if account.UID == 0 {
			severity = Critical
		}
		factors = append(factors, identityFactor{
			class: "identity-empty-password", text: "empty password", severity: severity, path: "/etc/shadow",
			quotes: cite(account.ShadowFile, account.ShadowLine, account.ShadowRaw),
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
			quotes: cite(account.Source, account.Line, account.Raw),
		})
	}
	for _, group := range groups {
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
			severity: severity, path: "/etc/group", quotes: cite(group.Source, group.Line, group.Raw),
		})
	}
	for _, grant := range state.Sudo {
		if grant.NoPasswd && grantApplies(grant, state, account) {
			factors = append(factors, identityFactor{
				class: "identity-sudo-nopasswd", text: "passwordless sudo " + grant.Command,
				severity: High, path: grant.File, quotes: cite(grant.File, grant.Line, grant.Raw),
			})
			break
		}
	}
	for _, key := range state.KeyCommands {
		if key.Account != account.Name {
			continue
		}
		severity := Medium
		if shellCommand(key.Command) {
			severity = High
		}
		class := Class("identity-key-command")
		if shellCommand(key.Command) {
			class = Class("identity-factor")
		}
		factors = append(factors, identityFactor{
			class: class, text: "authorized key forced command " + key.Command, severity: severity, path: key.File,
			quotes: cite(key.File, key.Line, key.Text),
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
	story := a.readAuthority(snapshot.Facts(factor.path))
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
func judgeIdentity(j *judgePass) []Coverage {
	snapshot, a, filter, add := j.snapshot, j.a, j.filter, j.add
	state := &snapshot.Identity
	if len(state.Accounts) == 0 && len(state.Sudo) == 0 && len(state.SSHD.Files) == 0 {
		return nil
	}
	if len(filter.PIDs) > 0 || len(filter.Units) > 0 {
		return nil
	}
	correlated := map[string]bool{}
	perAccount := map[string][]identityFactor{}
	for _, account := range state.Accounts {
		factors := identityFactors(state, account)
		perAccount[account.Name] = factors
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
			Evidence: evidence, Quotes: cite(account.Source, account.Line, account.Raw), Trace: trace,
		})
	}
	for _, account := range state.Accounts {
		if correlated[account.Name] {
			continue
		}
		for _, factor := range perAccount[account.Name] {
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
		add(Finding{
			Class: "identity-sudo-nopasswd", Severity: identitySeverity(snapshot, a, identityFactor{
				class: "identity-sudo-nopasswd", severity: High, path: grant.File,
			}),
			Title: "passwordless sudo grant", Path: grant.File, Origin: Unknown, Reach: RootAsset,
			Detail:   fmt.Sprintf("%s may run %s without a password", grant.User, grant.Command),
			Evidence: []string{fmt.Sprintf("%s:%d host %s runas %s", grant.File, grant.Line, grant.Host, grant.RunAs)},
			Quotes:   cite(grant.File, grant.Line, grant.Raw),
			Trace:    steps("sudoers "+grant.File, "grant "+grant.User, "command "+grant.Command),
		})
	}
	judgeSSHD(j)
	if !pathInScope("/etc/group", filter) {
		return nil
	}
	for _, group := range state.Groups {
		if group.Password != "" && !passwordKinds[group.Password] {
			add(Finding{
				Class: "identity-group-password", Severity: Medium,
				Title: "group password set", Path: group.Source, Origin: Unknown, Reach: RootAsset,
				Detail:   fmt.Sprintf("group %s can be entered with newgrp", group.Name),
				Evidence: []string{"the group password field is not x, * or !"},
				Quotes:   cite(group.Source, group.Line, group.Raw),
				Trace:    steps("group "+group.Name, "password set"),
			})
		}
	}
	return nil
}

func judgeSSHD(j *judgePass) {
	state, filter, add := &j.snapshot.Identity, j.filter, j.add
	if len(state.SSHD.Files) == 0 {
		return
	}
	sshPath := state.SSHD.Files[0]
	if !pathInScope(sshPath, filter) {
		return
	}
	defaultKeys := map[string]bool{
		".ssh/authorized_keys": true, ".ssh/authorized_keys2": true,
		"authorized_keys": true, "authorized_keys2": true, "none": true,
	}
	for _, value := range state.SSHD.AuthorizedKeysFile {
		if defaultKeys[value] {
			continue
		}
		severity := identitySeverity(j.snapshot, j.a, identityFactor{
			class: "identity-sshd-keyfile", severity: High, path: sshPath,
		})
		add(Finding{
			Class: "identity-sshd-keyfile", Severity: severity,
			Title: "sshd reads authorized keys from a non-default path",
			Path:  sshPath, Origin: Unknown, Reach: RootAsset,
			Detail:   "a redirected key file is a key-based backdoor surface",
			Evidence: []string{"AuthorizedKeysFile " + strings.Join(state.SSHD.AuthorizedKeysFile, " ")},
			Quotes:   cite(state.SSHD.KeyFile, state.SSHD.KeyLine, state.SSHD.KeyRaw),
			Trace:    steps("sshd_config", "AuthorizedKeysFile", value),
		})
		break
	}
}

func identityGraph(snapshot *Snapshot) *GraphView {
	state := &snapshot.Identity
	root := domainRoot("domain", "identity",
		"accounts, groups, sudo grants, shadow state and SSH keys", UserAsset)
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
		for _, group := range snapshot.Identity.groupsFor(account) {
			id := nodeKey("group", group.Name)
			root.link(node.ID, id, "member-of", "group", "high", "")
		}
		shadowState := "shadow hash set"
		if account.Locked {
			shadowState = "shadow locked"
		} else if emptyPassword(account) {
			shadowState = "shadow empty"
		}
		s := root.Node("secret", "shadow:"+account.Name, "shadow", "/etc/shadow", Unknown, reach, shadowState)
		root.link(node.ID, s.ID, "password", "shadow", "high", "")
		for _, key := range snapshot.Identity.KeyCommands {
			if key.Account != account.Name {
				continue
			}
			k := root.Node("key", key.Command, key.Command, key.File, Unknown, reach, "forced command")
			root.link(node.ID, k.ID, "authorized-by", "authorized_keys", "high", "")
		}
		for _, grant := range snapshot.Identity.Sudo {
			if !grantApplies(grant, state, account) {
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
