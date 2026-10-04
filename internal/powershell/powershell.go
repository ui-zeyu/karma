// Package powershell builds the PowerShell calls used by the Windows probes.
//
// Every Windows probe is one `powershell -Command` argument vector: the local
// exec runs it directly, without a shell; the output encoding is switched to
// UTF-8 (Windows PowerShell follows the OEM code page by default, which is GBK
// on a Chinese system, and karma decoding it as UTF-8 would produce garbage).
// The in-script `== ` section convention matches the Linux side and is emitted
// by the script itself.
package powershell

import "karma/internal/model"

var psExe = []string{"powershell", "-NoProfile", "-NonInteractive", "-Command"}

// UTF8Prefix is the encoding prefix each script starts with: native command
// output and our own output are both read and written as UTF-8.
const UTF8Prefix = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"

// PowerShell wraps one PowerShell script into a single Command call.
func PowerShell(script string) model.Command {
	argv := make([]string, 0, len(psExe)+1)
	argv = append(argv, psExe...)
	argv = append(argv, UTF8Prefix+script)
	return model.Command{Argv: argv}
}
