package audit

// Identity is a graph, not a file dump. Accounts, groups, sudo grants, shadow
// state and SSH keys are nodes; the edges are membership, grants, forced
// commands and key placement. A base image can carry a backdoor account with
// clean timestamps, and only the relations explain why it is a core problem.

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Account is one passwd row joined to its shadow row.
type Account struct {
	Name        string
	UID         int
	GID         int
	Home        string
	Shell       string
	Password    string
	Shadow      string
	ShadowKnown bool
	Locked      bool
	System      bool
	Source      string
	// Line and Raw are the passwd row the account was read from; the
	// Shadow* fields are the shadow row that answered for its password.
	Line       int
	Raw        string
	ShadowFile string
	ShadowLine int
	ShadowRaw  string
}

// Group is one /etc/group row.
type Group struct {
	Name     string
	GID      int
	Members  []string
	Password string
	Source   string
	Line     int
	Raw      string
}

// SudoGrant is one command a sudoers row grants.
type SudoGrant struct {
	User     string
	Host     string
	RunAs    string
	Command  string
	NoPasswd bool
	File     string
	Line     int
	// Raw is the logical line after continuation joining, trimmed.
	Raw string
}

// SSHDConfig is the security-relevant part of sshd_config.
type SSHDConfig struct {
	Files                  []string
	AuthorizedKeysFile     []string
	PermitRootLogin        string
	PasswordAuthentication string
	// KeyFile, KeyLine and KeyRaw name the first AuthorizedKeysFile
	// directive: the line that redirected the key search.
	KeyFile string
	KeyLine int
	KeyRaw  string
	// match counts conditional blocks; their directives apply to the
	// matched connections only, so the parser keeps them out of the global
	// posture.
	match int
}

// AuthorizedKeyCommand is one authorized_keys row with a forced command.
type AuthorizedKeyCommand struct {
	File string
	// Line and Text cite the authorized_keys row the command was read from.
	Line    int
	Text    string
	Account string
	Command string
}

// IdentityState is the parsed identity graph.
type IdentityState struct {
	Accounts    []Account
	Groups      []Group
	Sudo        []SudoGrant
	SSHD        SSHDConfig
	KeyCommands []AuthorizedKeyCommand

	// groupIndex is the membership index behind groupsFor, built once on
	// the first call instead of once per judgment.
	groupIndex *groupIndex
}

// groupIndex maps a primary gid and a member name to the group's position in
// Groups, so membership is an index lookup rather than a scan per question.
type groupIndex struct {
	byGID    map[int][]int
	byMember map[string][]int
}

// groupsFor answers the groups an account belongs to: every group that lists
// the account by name, plus its primary group, in Groups order and deduped
// by name — the same answer the membership scan gave, at index cost.
func (s *IdentityState) groupsFor(account Account) []Group {
	if s.groupIndex == nil {
		index := &groupIndex{byGID: map[int][]int{}, byMember: map[string][]int{}}
		for position, group := range s.Groups {
			index.byGID[group.GID] = append(index.byGID[group.GID], position)
			for _, member := range group.Members {
				index.byMember[member] = append(index.byMember[member], position)
			}
		}
		s.groupIndex = index
	}
	picks := map[int]bool{}
	for _, position := range s.groupIndex.byGID[account.GID] {
		picks[position] = true
	}
	for _, position := range s.groupIndex.byMember[account.Name] {
		picks[position] = true
	}
	var out []Group
	seen := map[string]bool{}
	for position, group := range s.Groups {
		if !picks[position] || seen[group.Name] {
			continue
		}
		seen[group.Name] = true
		out = append(out, group)
	}
	return out
}

// privilegedGroups are group names whose membership is an authority edge.
var privilegedGroups = map[string]Severity{
	"sudo": High, "wheel": High, "admin": High,
	"docker": High, "lxd": High, "disk": High, "shadow": High,
	"adm": Medium, "staff": Medium,
}

var passwordKinds = map[string]bool{"x": true, "*": true, "!": true, "!!": true}

// collectIdentity reads the identity files and parses their records.
func collectIdentity(ctx context.Context, snapshot *Snapshot) []Coverage {
	facts := snapshot.classify
	state := &snapshot.Identity
	var paths []string
	read := func(path string) (string, bool) {
		data, err := readCapped(path, 1<<20)
		if err != nil {
			return "", false
		}
		paths = append(paths, path)
		return string(data), true
	}
	var gaps []Coverage
	passwd, ok := read("/etc/passwd")
	if !ok {
		gaps = append(gaps, coverageAbsent("identity", "identity: /etc/passwd is unreadable"))
	}
	shadow, shadowOK := read("/etc/shadow")
	group, groupOK := read("/etc/group")
	if !shadowOK {
		gaps = append(gaps, coverageGap("identity", "identity: /etc/shadow is unreadable; empty-password checks are skipped"))
	}
	if !groupOK {
		gaps = append(gaps, coverageGap("identity", "identity: /etc/group is unreadable; group membership checks are skipped"))
	}
	state.Accounts = parsePasswd(passwd, "/etc/passwd")
	applyShadow(state.Accounts, parseShadow(shadow, "/etc/shadow"))
	state.Groups = parseGroup(group, "/etc/group")

	sudoers := []string{"/etc/sudoers"}
	if matches, _ := filepath.Glob("/etc/sudoers.d/*"); len(matches) > 0 {
		sudoers = append(sudoers, matches...)
	}
	for _, file := range sudoers {
		if _, err := readCapped(file, 1<<20); err != nil {
			// An unreadable sudoers include hides every grant it carries:
			// the check says so instead of going quiet.
			gaps = append(gaps, coverageGap("identity", "identity: sudoers file is unreadable; its grants are skipped: "+file))
			continue
		}
		paths = append(paths, file)
	}
	state.Sudo = parseSudoersFiles(sudoers, 0)

	sshdFiles := []string{"/etc/ssh/sshd_config"}
	if matches, _ := filepath.Glob("/etc/ssh/sshd_config.d/*.conf"); len(matches) > 0 {
		sshdFiles = append(sshdFiles, matches...)
	}
	for _, file := range sshdFiles {
		if _, err := readCapped(file, 1<<20); err != nil && file != "/etc/ssh/sshd_config" {
			gaps = append(gaps, coverageGap("identity", "identity: sshd_config include is unreadable; its directives are skipped: "+file))
		}
	}
	state.SSHD = parseSSHD(sshdFiles, 0)
	paths = append(paths, state.SSHD.Files...)
	state.KeyCommands = parseAuthorizedKeyCommands()
	for _, key := range state.KeyCommands {
		paths = append(paths, key.File)
	}
	if len(state.SSHD.Files) == 0 {
		gaps = append(gaps, coverageAbsent("identity", "identity: no sshd_config was readable"))
	}

	if len(paths) > 0 {
		for _, path := range paths {
			remember(snapshot, path, facts(path))
		}
	}
	return gaps
}

// nisCompatRow reports a NIS compatibility entry (`+` or `-` in the name
// column): a directory reference, not a local record.
func nisCompatRow(line string) bool {
	return strings.HasPrefix(line, "+") || strings.HasPrefix(line, "-")
}

// parsePasswd reads colon-separated passwd records. Malformed rows are
// returned as coverage rather than guessed at.
func parsePasswd(text, source string) []Account {
	var accounts []Account
	for index, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || nisCompatRow(line) {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != 7 {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		gid, _ := strconv.Atoi(fields[3])
		accounts = append(accounts, Account{
			Name: fields[0], UID: uid, GID: gid, Home: fields[5], Shell: fields[6],
			Password: fields[1], System: uid < 1000 && uid != 0, Source: source,
			Line: index + 1, Raw: line,
		})
	}
	return accounts
}

func applyShadow(accounts []Account, shadow map[string]Account) {
	for index := range accounts {
		if row, ok := shadow[accounts[index].Name]; ok {
			accounts[index].Shadow = row.Shadow
			accounts[index].ShadowKnown = true
			accounts[index].Locked = row.Locked
			accounts[index].ShadowFile = row.Source
			accounts[index].ShadowLine = row.Line
			accounts[index].ShadowRaw = row.Raw
		}
	}
}

// parseShadow keeps only the fields the identity graph uses.
func parseShadow(text, source string) map[string]Account {
	rows := map[string]Account{}
	for index, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || nisCompatRow(line) {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != 9 {
			continue
		}
		hash := fields[1]
		locked := strings.HasPrefix(hash, "!") || hash == "*"
		rows[fields[0]] = Account{Name: fields[0], Shadow: hash, Locked: locked, Source: source, Line: index + 1, Raw: line}
	}
	return rows
}

func parseGroup(text, source string) []Group {
	var groups []Group
	for index, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || nisCompatRow(line) {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != 4 {
			continue
		}
		gid, _ := strconv.Atoi(fields[2])
		var members []string
		for _, member := range strings.Split(fields[3], ",") {
			if member = strings.TrimSpace(member); member != "" {
				members = append(members, member)
			}
		}
		groups = append(groups, Group{
			Name: fields[0], GID: gid, Members: members, Password: fields[1], Source: source,
			Line: index + 1, Raw: line,
		})
	}
	return groups
}

// sudoersTables holds the alias definitions every file shares: a grant may
// name an alias declared in another include.
type sudoersTables struct {
	userAliases map[string][]string
	cmdAliases  map[string][]string
}

func newSudoersTables() *sudoersTables {
	return &sudoersTables{
		userAliases: map[string][]string{},
		cmdAliases:  map[string][]string{},
	}
}

// parseSudoersFiles reads sudoers and its includes in one pass, then expands
// the aliases across the whole statement set. A grant may name an alias
// declared in another include, and an include's own grants resolve exactly
// once — the two-pass re-read dropped both.
func parseSudoersFiles(files []string, depth int) []SudoGrant {
	return resolveSudoers(collectSudoers(files, depth), newSudoersTables())
}

// sudoersStmt is one parsed sudoers row: an alias definition, a grant, or an
// include. Statements are collected first and resolved second, so alias
// order across files stops mattering.
type sudoersStmt struct {
	kind    string // user-alias, cmnd-alias, grant, include
	alias   sudoersAliasRow
	grant   rawGrant
	include string
}

// rawGrant is one grant row before its user and command aliases expand.
type rawGrant struct {
	users    []string
	host     string
	runAs    string
	segments []grantSegment
	file     string
	line     int
	raw      string
}

type grantSegment struct {
	command  string
	noPasswd bool
}

// collectSudoers reads the file set and its includes into statements. Each
// file is read exactly once; includes recurse under the same depth cap.
func collectSudoers(files []string, depth int) []sudoersStmt {
	if depth > 4 {
		return nil
	}
	var stmts []sudoersStmt
	for _, file := range files {
		data, err := readCapped(file, 1<<20)
		if err != nil {
			continue
		}
		for _, stmt := range sudoersStatements(string(data), file) {
			stmts = append(stmts, stmt)
			if stmt.kind == "include" {
				matches, _ := filepath.Glob(stmt.include)
				slices.Sort(matches)
				stmts = append(stmts, collectSudoers(matches, depth+1)...)
			}
		}
	}
	return stmts
}

// sudoersStatements parses one sudoers file's rows into statements. Alias
// values and grant segments stay unexpanded; resolution owns them.
func sudoersStatements(text, file string) []sudoersStmt {
	var stmts []sudoersStmt
	lines := strings.Split(text, "\n")
	for index := 0; index < len(lines); index++ {
		line := strings.TrimSpace(lines[index])
		for strings.HasSuffix(line, "\\") && index+1 < len(lines) {
			index++
			line = strings.TrimSpace(strings.TrimSuffix(line, "\\") + " " + strings.TrimSpace(lines[index]))
		}
		if line == "" {
			continue
		}
		if isSudoersInclude(line) {
			paths := sudoersIncludes(line)
			if len(paths) > 0 {
				stmts = append(stmts, sudoersStmt{kind: "include", include: paths[0]})
			}
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "@") {
			continue
		}
		if aliasRow, aliasKind, ok := sudoersAlias(line); ok {
			kind := map[string]string{
				"User_Alias": "user-alias",
				"Cmnd_Alias": "cmnd-alias",
			}[aliasKind]
			stmts = append(stmts, sudoersStmt{kind: kind, alias: aliasRow})
			continue
		}
		if strings.HasPrefix(line, "Defaults") {
			continue
		}
		left, right, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		leftFields := strings.Fields(left)
		if len(leftFields) == 0 {
			continue
		}
		grant := rawGrant{
			users: strings.Split(leftFields[0], ","),
			host:  strings.Join(leftFields[1:], " "),
			file:  file,
			line:  index + 1,
			raw:   line,
		}
		right = strings.TrimSpace(right)
		if strings.HasPrefix(right, "(") {
			if end := strings.IndexByte(right, ')'); end >= 0 {
				grant.runAs = strings.TrimSpace(right[1:end])
				right = strings.TrimSpace(right[end+1:])
			}
		}
		for _, segment := range strings.Split(right, ",") {
			segment = strings.TrimSpace(segment)
			if segment == "" {
				continue
			}
			part := grantSegment{}
			if value, ok := strings.CutPrefix(segment, "NOPASSWD:"); ok {
				part.noPasswd = true
				segment = strings.TrimSpace(value)
			} else if value, ok := strings.CutPrefix(segment, "PASSWD:"); ok {
				segment = strings.TrimSpace(value)
			}
			if segment == "" {
				continue
			}
			part.command = segment
			grant.segments = append(grant.segments, part)
		}
		if len(grant.segments) > 0 {
			stmts = append(stmts, sudoersStmt{kind: "grant", grant: grant})
		}
	}
	return stmts
}

// resolveSudoers fills the alias tables from the whole statement set, then
// expands every grant against them.
func resolveSudoers(stmts []sudoersStmt, tables *sudoersTables) []SudoGrant {
	for _, stmt := range stmts {
		switch stmt.kind {
		case "user-alias":
			tables.userAliases[stmt.alias.name] = stmt.alias.values
		case "cmnd-alias":
			tables.cmdAliases[stmt.alias.name] = stmt.alias.values
		}
	}
	var grants []SudoGrant
	seen := map[string]bool{}
	add := func(grant SudoGrant) {
		key := fmt.Sprintf("%s:%d:%s:%s", grant.File, grant.Line, grant.User, grant.Command)
		if seen[key] {
			return
		}
		seen[key] = true
		grants = append(grants, grant)
	}
	for _, stmt := range stmts {
		if stmt.kind != "grant" {
			continue
		}
		grant := stmt.grant
		users := expandSudoers(grant.users, tables.userAliases, nil)
		for _, segment := range grant.segments {
			for _, command := range expandSudoers([]string{segment.command}, tables.cmdAliases, nil) {
				for _, user := range users {
					add(SudoGrant{
						User: user, Host: grant.host, RunAs: grant.runAs,
						Command: command, NoPasswd: segment.noPasswd,
						File: grant.file, Line: grant.line, Raw: grant.raw,
					})
				}
			}
		}
	}
	return grants
}

var sudoersInclude = regexp.MustCompile(`(?m)^\s*[#@]include(dir)?\s+(\S+)`)

func sudoersIncludes(text string) []string {
	var paths []string
	for _, match := range sudoersInclude.FindAllStringSubmatch(text, -1) {
		path := match[2]
		if !filepath.IsAbs(path) {
			path = filepath.Join("/etc", path)
		}
		paths = append(paths, path)
	}
	return paths
}

// isSudoersInclude answers whether the row is an include or includedir.
func isSudoersInclude(line string) bool {
	return sudoersInclude.MatchString(line)
}

// parseSudoers reads one file's grants, expanded against the caller's alias
// tables. The file-set entry point is parseSudoersFiles; this shape stays
// for single-file callers and tests.
func parseSudoers(text, file string, tables *sudoersTables) []SudoGrant {
	return resolveSudoers(sudoersStatements(text, file), tables)
}

type sudoersAliasRow struct {
	name   string
	values []string
}

// sudoersAlias reads one `User_Alias NAME = value, value` row.
func sudoersAlias(line string) (sudoersAliasRow, string, bool) {
	for _, kind := range []string{"User_Alias", "Cmnd_Alias"} {
		rest, ok := strings.CutPrefix(line, kind+" ")
		if !ok {
			continue
		}
		name, values, found := strings.Cut(rest, "=")
		if !found {
			return sudoersAliasRow{}, kind, false
		}
		name = strings.TrimSpace(name)
		if name == "" {
			return sudoersAliasRow{}, kind, false
		}
		var list []string
		for _, value := range strings.Split(values, ",") {
			if value = strings.TrimSpace(value); value != "" {
				list = append(list, value)
			}
		}
		return sudoersAliasRow{name: name, values: list}, kind, true
	}
	return sudoersAliasRow{}, "", false
}

// expandSudoers resolves alias names to their values, one level deep, keeping
// the concrete spellings. A cycle stops at the first repeat.
func expandSudoers(values []string, aliases map[string][]string, seen map[string]bool) []string {
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if list, ok := aliases[value]; ok && !seen[value] {
			next := map[string]bool{}
			for name := range seen {
				next[name] = true
			}
			next[value] = true
			out = append(out, expandSudoers(list, aliases, next)...)
			continue
		}
		out = append(out, value)
	}
	return out
}

// parseSSHD reads sshd_config and its Include files the way sshd applies
// them: first match wins, an Include is expanded where it appears, and the
// directives inside a Match block stay conditional. The program hooks are
// activation edges elsewhere; this parser keeps the authentication posture.
func parseSSHD(files []string, depth int) SSHDConfig {
	state := &sshdState{seen: map[string]bool{}}
	for _, file := range files {
		parseSSHDFile(state, file, depth)
	}
	return state.config
}

type sshdState struct {
	config SSHDConfig
	seen   map[string]bool
	match  int
}

func parseSSHDFile(state *sshdState, file string, depth int) {
	if depth > 4 {
		return
	}
	data, err := readCapped(file, 1<<20)
	if err != nil {
		return
	}
	state.config.Files = append(state.config.Files, file)
	for index, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		raw := line
		// sshd accepts `Key value` and `Key=value`; normalize the latter.
		line = strings.Replace(line, "=", " ", 1)
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.ToLower(fields[0])
		value := strings.Join(fields[1:], " ")
		switch key {
		case "match":
			// A conditional block: every directive until the next Match or
			// the end of file applies to the matched connections only.
			state.match++
			state.config.match = state.match
			continue
		case "include":
			pattern := fields[1]
			if !filepath.IsAbs(pattern) {
				pattern = filepath.Join("/etc/ssh", pattern)
			}
			matches, _ := filepath.Glob(pattern)
			slices.Sort(matches)
			for _, match := range matches {
				parseSSHDFile(state, match, depth+1)
			}
			continue
		}
		if state.match > 0 {
			// Inside a Match block: conditional, so the global posture is
			// untouched. The block itself stays visible on the graph node.
			continue
		}
		if state.seen[key] {
			// sshd reads the first occurrence of a keyword.
			continue
		}
		state.seen[key] = true
		switch key {
		case "authorizedkeysfile":
			state.config.AuthorizedKeysFile = append(state.config.AuthorizedKeysFile, fields[1:]...)
			state.config.KeyFile = file
			state.config.KeyLine = index + 1
			state.config.KeyRaw = raw
		case "permitrootlogin":
			state.config.PermitRootLogin = strings.ToLower(value)
		case "passwordauthentication":
			state.config.PasswordAuthentication = strings.ToLower(value)
		}
	}
}

var commandOption = regexp.MustCompile(`(?i)\bcommand="([^"]*)"`)

// parseAuthorizedKeyCommands reads forced commands from the key files. The
// key's own file is the graph node; the account is derived from the path.
func parseAuthorizedKeyCommands() []AuthorizedKeyCommand {
	var files []string
	for _, pattern := range []string{
		"/root/.ssh/authorized_keys",
		"/home/*/.ssh/authorized_keys",
		"/etc/ssh/authorized_keys",
		"/etc/ssh/authorized_keys.d/*",
	} {
		matches, _ := filepath.Glob(pattern)
		files = append(files, matches...)
	}
	var commands []AuthorizedKeyCommand
	for _, file := range files {
		data, err := readCapped(file, 1<<20)
		if err != nil {
			continue
		}
		account := accountForPath(file)
		for index, raw := range strings.Split(string(data), "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			match := commandOption.FindStringSubmatch(line)
			if len(match) != 2 || match[1] == "" {
				continue
			}
			commands = append(commands, AuthorizedKeyCommand{
				File: file, Line: index + 1, Text: line,
				Account: account, Command: match[1],
			})
		}
	}
	return commands
}

func accountForPath(path string) string {
	if strings.HasPrefix(path, "/root/") {
		return "root"
	}
	if rest, ok := strings.CutPrefix(path, "/home/"); ok {
		if slash := strings.IndexByte(rest, '/'); slash > 0 {
			return rest[:slash]
		}
	}
	return ""
}
