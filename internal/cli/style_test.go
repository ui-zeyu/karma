// Skeleton styling follows the stream: a capture buffer is not a terminal, so
// help and error output stay plain, and a forced 256-color profile paints bold
// headers and names with muted descriptions.

package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/muesli/termenv"
)

func TestSkeletonStylesFollowTheStream(t *testing.T) {
	var buf bytes.Buffer
	if st := stylesFor(&buf); st.bold("x") != "x" || st.err("x") != "x" {
		t.Fatalf("a capture buffer should render plain, got %q %q", st.bold("x"), st.err("x"))
	}
}

func TestStyledUsageCarriesColor(t *testing.T) {
	root := newRootCmd("0.0.0")
	// Usage rendering normally happens after Execute, which is what registers
	// the help flag; a direct render has to do it itself.
	root.InitDefaultHelpFlag()

	var plain bytes.Buffer
	styledUsageWith(&plain, root, stylesFor(&plain))
	if strings.Contains(plain.String(), "\x1b[") {
		t.Fatalf("detected styling on a capture buffer should be plain: %q", plain.String())
	}

	var buf bytes.Buffer
	styledUsageWith(&buf, root, stylesForProfile(&buf, termenv.ANSI256))
	got := buf.String()
	for _, want := range []string{
		"▌ USAGE",
		"\x1b[1mkarma\x1b[0m\x1b[38;5;244m [flags]",
		"▌ COMMANDS",
		"\x1b[1mlist",
		"\x1b[38;5;244m  List the check catalog",
		"▌ FLAGS",
		"\x1b[1m-h, --help",
		"\x1b[38;5;244m   help for karma",
		"\x1b[38;5;244mUse \"karma [command] --help\"",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("styled usage should contain %q, got:\n%q", want, got)
		}
	}
}

func TestReportErrorColorsFollowTheStream(t *testing.T) {
	root := newRootCmd("0.0.0")
	root.InitDefaultHelpFlag()
	err := usagef(root, "unknown command %q. Did you mean: %s", "lst", "list")

	var plain bytes.Buffer
	if code := reportError(&plain, err); code != 0 {
		t.Fatalf("a usage error should return 0, got %d", code)
	}
	if strings.Contains(plain.String(), "\x1b[") {
		t.Fatalf("error output on a capture buffer should be plain: %q", plain.String())
	}

	var buf bytes.Buffer
	reportErrorWith(&buf, err, stylesForProfile(&buf, termenv.ANSI256))
	got := buf.String()
	for _, want := range []string{
		// termenv renders the ANSI bright colors 9 and 11 as 91/93
		"\x1b[91mkarma: unknown command \"lst\". ",
		"\x1b[93mDid you mean: list",
		"\x1b[1m-h, --help",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("styled error should contain %q, got:\n%q", want, got)
		}
	}
}
