// The kernel release on platforms without a uname syscall binding: empty, the
// same answer a failed `uname -r` round trip would leave.

//go:build !unix

package facts

func localKernel() string { return "" }
