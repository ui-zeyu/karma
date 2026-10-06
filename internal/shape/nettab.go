// Neighbor and route shaping: `ip neigh` and `ip route` write key-value rows
// whose columns drift with every address, so the panel reads them as the
// tables they mean. Each shaper knows exactly the words iproute2 writes for
// its own output — a row carrying anything else (the arp(8) and route(8)
// fallback probes print their own aligned tables) declines, and that body
// reaches the panel exactly as the tool wrote it.

package shape

import (
	"strings"

	"karma/internal/model"
)

// neighFlagWords are the bare flag words ip neigh prints between the lladdr
// and the state.
var neighFlagWords = map[string]bool{
	"router": true, "proxy": true, "managed": true,
	"extern_learn": true, "offload": true, "extern_valid": true,
}

// neighStateWords are the NUD states ip neigh prints; several can appear.
var neighStateWords = map[string]bool{
	"INCOMPLETE": true, "REACHABLE": true, "STALE": true, "DELAY": true,
	"PROBE": true, "FAILED": true, "NOARP": true, "PERMANENT": true,
	"NONE": true,
}

// NeighTable turns `ip neigh` rows into a column table: address, device,
// link-layer address, the flag words, and the states.
func NeighTable(title, body string) *model.Shaped {
	table := NewTable("ADDRESS", "DEV", "LLADDR", "FLAGS", "STATE")
	for _, line := range lines(body) {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		var (
			dev, lladdr           string
			flagWords, stateWords []string
		)
		addr := fields[0]
		sawDev, sawLL := false, false
		for i := 1; i < len(fields); {
			switch fields[i] {
			case "dev":
				if sawDev || i+1 >= len(fields) {
					return nil
				}
				sawDev, dev, i = true, fields[i+1], i+2
			case "lladdr":
				if sawLL || i+1 >= len(fields) {
					return nil
				}
				sawLL, lladdr, i = true, fields[i+1], i+2
			default:
				if neighFlagWords[fields[i]] {
					flagWords = append(flagWords, fields[i])
					i++
					continue
				}
				if neighStateWords[fields[i]] {
					stateWords = append(stateWords, fields[i])
					i++
					continue
				}
				return nil
			}
		}
		if !sawDev {
			return nil
		}
		table.Add(addr, dev, lladdr, strings.Join(flagWords, " "), strings.Join(stateWords, " "))
	}
	if table.Empty() {
		return nil
	}
	return shaped(table.String())
}

// routeColumns puts each `ip route` key word in its column: destination,
// gateway, device, protocol, scope, source, metric. A row with any other word
// (onlink, mtu, a nexthop id) declines the whole body.
var routeColumns = map[string]int{
	"via": 1, "dev": 2, "proto": 3, "scope": 4, "src": 5, "metric": 6,
}

// routeTailWords are the two fields iproute2 adds to an IPv6 row and the
// in-process netlink reader cannot decode (its own comment says so): the
// default preference and a route lifetime. They carry no verdict and reach the
// panel from one channel only, so the shaper reads them out of the row rather
// than into a column of its own — which is what lets a route read the same on
// both channels. Both are in the raw text --save writes.
var routeTailWords = map[string]bool{"pref": true, "expires": true}

// RouteTable turns `ip route` rows into a column table: destination, gateway,
// device, protocol, scope, source, metric.
func RouteTable(title, body string) *model.Shaped {
	table := NewTable("DEST", "VIA", "DEV", "PROTO", "SCOPE", "SRC", "METRIC")
	for _, line := range lines(body) {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		var row [7]string
		row[0] = fields[0]
		for i := 1; i < len(fields); {
			if routeTailWords[fields[i]] && i+1 < len(fields) {
				i += 2
				continue
			}
			col, known := routeColumns[fields[i]]
			if !known || i+1 >= len(fields) {
				return nil
			}
			row[col] = fields[i+1]
			i += 2
		}
		table.Add(row[:]...)
	}
	if table.Empty() {
		return nil
	}
	return shaped(table.String())
}
