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
	// ipv6Shape is an unbracketed IPv6 address: hex digits, colons and dots only.
	ipv6Shape = regexp.MustCompile(`^[0-9a-fA-F:.]+$`)
)

// SSHDestination is a parsed SSH destination. When User is empty the implementation uses the local current user.
type SSHDestination struct {
	User string
	Host string
	Port int
}

// Display is the destination description in user@host form, appending the port when it is not 22.
func (d SSHDestination) Display() string {
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
func ParseSSHDestination(target string) (SSHDestination, error) {
	stripped := strings.TrimSpace(target)
	if strings.HasPrefix(stripped, "ssh://") {
		return parseURI(stripped)
	}
	return parseShort(stripped)
}

func parseShort(target string) (SSHDestination, error) {
	if strings.Contains(target, ":") {
		return SSHDestination{}, fmt.Errorf("\"%s\" is not a valid destination: non-URI form has no colon, use ssh://[addr] for IPv6", target)
	}
	matched := userAtHost.FindStringSubmatch(target)
	if matched == nil || matched[userAtHost.SubexpIndex("host")] == "" {
		return SSHDestination{}, fmt.Errorf("\"%s\" is not a valid destination, expected form user@host", target)
	}
	return SSHDestination{
		User: matched[userAtHost.SubexpIndex("user")],
		Host: matched[userAtHost.SubexpIndex("host")],
		Port: 22,
	}, nil
}

func parseURI(uri string) (SSHDestination, error) {
	matched := uriForm.FindStringSubmatch(uri)
	if matched == nil || matched[uriForm.SubexpIndex("host")] == "" {
		return SSHDestination{}, fmt.Errorf("\"%s\" is not a valid ssh:// URI, expected form ssh://user@host:22", uri)
	}
	hostPart := matched[uriForm.SubexpIndex("host")]
	bracket := bracketedV6.FindStringSubmatch(hostPart)
	var host string
	switch {
	case bracket != nil:
		host = bracket[bracketedV6.SubexpIndex("addr")]
	case !strings.Contains(hostPart, ":"):
		host = hostPart
	case ipv6Shape.MatchString(hostPart):
		// The URI's port group only takes digits, so an unbracketed IPv6 address
		// stays in the host part: "ssh://::1" arrives here.
		return SSHDestination{}, fmt.Errorf("\"%s\": IPv6 address requires brackets, expected form ssh://user@[::1]:22", hostPart)
	default:
		// Likewise a non-numeric port stays in the host part; say which port it
		// was meant to be rather than blaming brackets.
		_, portText, _ := strings.Cut(hostPart, ":")
		return SSHDestination{}, fmt.Errorf("\"%s\": port %q is not a number", uri, portText)
	}
	portText := matched[uriForm.SubexpIndex("port")]
	port := 22
	if portText != "" {
		value, err := strconv.Atoi(portText)
		if err != nil {
			return SSHDestination{}, fmt.Errorf("\"%s\" is not a valid ssh:// URI, expected form ssh://user@host:22", uri)
		}
		port = value
	}
	if port < 1 || port > MaxPort {
		return SSHDestination{}, fmt.Errorf("\"%s\": port %d out of range 1-%d", uri, port, MaxPort)
	}
	return SSHDestination{User: matched[uriForm.SubexpIndex("user")], Host: host, Port: port}, nil
}
