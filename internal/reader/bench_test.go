package reader_test

import (
	"strings"
	"testing"

	"karma/internal/model"
	"karma/internal/reader"
)

// BenchmarkAnalyzeListing measures the reading pipeline on its bulk case: a
// directory listing of twenty thousand rows read against a full rule pack and
// the blank-line filter (hits are rare, as on a normal host).
func BenchmarkAnalyzeListing(b *testing.B) {
	rules := []model.Rule{
		model.NewRule("shell-interactive", `\b(?:ba|z|da|k)?sh\s+-i\b`, model.Critical, "interactive shell"),
		model.NewRule("netcat-exec", `\bnc(?:1|\.openbsd)?\b[^|\n]*\s-e\b`, model.Critical, "netcat -e"),
		model.NewRule("download-to-shell", `\b(?:curl|wget)\b[^|\n]*\|\s*sh\b`, model.Critical, "download to shell"),
		model.NewRule("base64-decode", `\bbase64\s+(?:--decode|-d)\b`, model.Medium, "base64 decode"),
		model.NewRule("ld-so-preload", `\bld\.so\.preload\b`, model.High, "dynamic linker preload"),
		model.NewRule("deleted-binary", `\(deleted\)`, model.Critical, "deleted binary"),
		model.NewRule("hidden-tmp-path", `(?:(?:var/)?tmp|dev/shm)/\.[A-Za-z0-9_.-]`, model.High, "hidden file in tmp"),
		model.NewRule("hidden-nonhome-path", `(?:opt|srv|usr/local|etc)/\.[A-Za-z0-9_.-]`, model.Medium, "hidden file"),
		model.NewRule("private-key-block", `-----BEGIN [A-Z0-9 ]*PRIVATE KEY`, model.High, "private key block"),
		model.NewRule("known-malware-name", `\b(?:xmrig|kinsing|ddgs|masscan)\b`, model.Critical, "malware name"),
		model.NewRule("web-script", `\.(?:php|jsp|jspx)$`, model.Medium, "web script"),
		model.NewRule("mtime-outlier", `^! `, model.Medium, "mtime outlier"),
	}
	filters := []model.LineFilter{model.NewFilter("blank", `^[ \t\r]*$`, model.FilterDrop)}

	var body strings.Builder
	for i := 0; i < 20000; i++ {
		body.WriteString("-rw-r--r--  1 root root     4096 Mar 15 10:20 report-")
		body.WriteString(strings.Repeat("x", i%7+1))
		body.WriteString(".log\n")
	}
	text := body.String()

	b.ReportAllocs()
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if len(reader.Analyze(text, rules, filters, nil, 0, model.FloorAll).Sections) == 0 {
			b.Fatal("no sections")
		}
	}
}
