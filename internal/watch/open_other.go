//go:build !linux

package watch

// Open has no source outside Linux: the process and socket tables are kernel
// interfaces, and the fallbacks need them too.
func Open(Family, Options) (Source, error) { return nil, ErrUnsupported }
