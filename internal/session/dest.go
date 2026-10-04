// SSH destination parsing: supports both the OpenSSH-style and ssh:// URI forms. Pure function, opens no connection.
package session

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// MaxPort is the upper port bound.
const MaxPort = 65535

var (
	userAtHost  = regexp.MustCompile(`^(?:(?P<user>[^@]+)@)?(?P<host>[^:@]+)$`)
	uriForm     = regexp.MustCompile(`^ssh://(?:(?P<user>[^@/]+)@)?(?P<host>[^/]+?)(?::(?P<port>\d+))?$`)
	bracketedV6 = regexp.MustCompile(`^\[(?P<addr>[0-9a-fA-F:.]+)\]$`)
)

// SshDestination is a parsed SSH destination. When User is empty the implementation uses the local current user.
type SshDestination struct {
	User string
	Host string
	Port int
}

// Display is the destination description in user@host form, appending the port when it is not 22.
func (d SshDestination) Display() string {
	base := d.Host
	if d.User != "" {
		base = d.User + "@" + d.Host
	}
	if d.Port != 22 {
		return fmt.Sprintf("%s:%d", base, d.Port)
	}
	return base
}

// ParseSSHDestination parses `[user@]host`, `ssh://[user@]host[:port]` and IPv6
// URIs. A non-URI host has no colon; IPv6 uses the URI bracketed form.
func ParseSSHDestination(target string) (SshDestination, error) {
	stripped := strings.TrimSpace(target)
	if strings.HasPrefix(stripped, "ssh://") {
		return parseURI(stripped)
	}
	return parseShort(stripped)
}

func parseShort(target string) (SshDestination, error) {
	if strings.Contains(target, ":") {
		return SshDestination{}, fmt.Errorf("\"%s\" is not a valid destination: non-URI form has no colon, use ssh://[addr] for IPv6", target)
	}
	matched := userAtHost.FindStringSubmatch(target)
	if matched == nil || matched[userAtHost.SubexpIndex("host")] == "" {
		return SshDestination{}, fmt.Errorf("\"%s\" is not a valid destination, expected form user@host", target)
	}
	return SshDestination{
		User: matched[userAtHost.SubexpIndex("user")],
		Host: matched[userAtHost.SubexpIndex("host")],
		Port: 22,
	}, nil
}

func parseURI(uri string) (SshDestination, error) {
	matched := uriForm.FindStringSubmatch(uri)
	if matched == nil || matched[uriForm.SubexpIndex("host")] == "" {
		return SshDestination{}, fmt.Errorf("\"%s\" is not a valid ssh:// URI, expected form ssh://user@host:22", uri)
	}
	hostPart := matched[uriForm.SubexpIndex("host")]
	var host string
	if bracket := bracketedV6.FindStringSubmatch(hostPart); bracket != nil {
		host = bracket[bracketedV6.SubexpIndex("addr")]
	} else if strings.Contains(hostPart, ":") {
		return SshDestination{}, fmt.Errorf("\"%s\": IPv6 address requires brackets, expected form ssh://user@[::1]:22", hostPart)
	} else {
		host = hostPart
	}
	portText := matched[uriForm.SubexpIndex("port")]
	port := 22
	if portText != "" {
		value, err := strconv.Atoi(portText)
		if err != nil {
			return SshDestination{}, fmt.Errorf("\"%s\" is not a valid ssh:// URI, expected form ssh://user@host:22", uri)
		}
		port = value
	}
	if port < 1 || port > MaxPort {
		return SshDestination{}, fmt.Errorf("\"%s\": port %d out of range 1-%d", uri, port, MaxPort)
	}
	return SshDestination{User: matched[uriForm.SubexpIndex("user")], Host: host, Port: port}, nil
}
