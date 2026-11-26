//go:build linux

package watch

import "sort"

// procKey is one process over its lifetime: the pid alone is reused, the
// starttime (clock ticks after boot) is not.
type procKey struct {
	PID   int
	Start uint64
}

// procState is the cached facts of one process. The poll reads stat every tick
// for the key and the rest of these only when the key is new.
type procState struct {
	Key     procKey
	PPID    int
	UID     int
	Comm    string
	Exe     string
	Cmdline string
	Args    []string
	Cwd     string
}

// sockKey is one socket over its lifetime. The inode is part of the key: a
// state change on the same socket is not a new event, while the TIME-WAIT
// socket the kernel creates after close is a new inode and prints.
type sockKey struct {
	Proto string
	Local string
	Peer  string
	Inode uint64
}

// sockState is the cached fact of one socket.
type sockState struct {
	Key   sockKey
	State string
	UID   int
}

// diffProc separates new keys from gone keys. A pid reused with a new
// starttime appears as both an exit and an exec, which is the honest reading.
func diffProc(prev, cur map[procKey]procState) (started, ended []procState) {
	for key, state := range cur {
		if _, ok := prev[key]; !ok {
			started = append(started, state)
		}
	}
	for key, state := range prev {
		if _, ok := cur[key]; !ok {
			ended = append(ended, state)
		}
	}
	sort.Slice(started, func(i, j int) bool { return started[i].Key.PID < started[j].Key.PID })
	sort.Slice(ended, func(i, j int) bool { return ended[i].Key.PID < ended[j].Key.PID })
	return started, ended
}

// newSockets returns the keys that were not in prev, ordered so two runs
// against the same table print the same lines.
func newSockets(prev, cur map[sockKey]sockState) []sockState {
	var added []sockState
	for key, state := range cur {
		if _, ok := prev[key]; !ok {
			added = append(added, state)
		}
	}
	sort.Slice(added, func(i, j int) bool {
		a, b := added[i].Key, added[j].Key
		if a.Proto != b.Proto {
			return a.Proto < b.Proto
		}
		if a.Local != b.Local {
			return a.Local < b.Local
		}
		if a.Peer != b.Peer {
			return a.Peer < b.Peer
		}
		return a.Inode < b.Inode
	})
	return added
}
