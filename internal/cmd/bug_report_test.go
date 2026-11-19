package cmd

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
)

func TestBugReportHelp(t *testing.T) {
	t.Parallel()

	b := bytes.NewBufferString("")
	root := newRootCmd()
	root.SetOut(b)
	root.SetArgs([]string{"bug-report", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}

	out := b.String()
	for _, want := range []string{"bug-report", "runtime information", "default browser"} {
		if !strings.Contains(out, want) {
			t.Errorf("bug-report help missing %q:\n%s", want, out)
		}
	}
}

func TestBugReportBodyContainsSystemInfo(t *testing.T) {
	t.Parallel()

	body := bugReportBody("v1.0.0")

	wants := []string{
		"## jose version\nv1.0.0",
		"## Environment",
		"- OS: " + runtime.GOOS,
		"- Architecture: " + runtime.GOARCH,
		"- Go: " + runtime.Version(),
		"## Description (About the problem)",
		"## Steps to reproduce",
		"## Expected behavior",
		"## Additional details",
	}
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("bug report body missing %q:\n%s", want, body)
		}
	}

	// The old template had broken "**" suffixes on its headers; make sure none
	// remain.
	if strings.Contains(body, "details**") || strings.Contains(body, "version**") {
		t.Errorf("bug report body still contains broken markdown header:\n%s", body)
	}
}

// Not parallel: it writes the Version global, which every parallel test that
// builds a root command reads through resolveVersion.
func TestBugReportFallbackWhenBrowserUnavailable(t *testing.T) {
	orgVer := Version
	Version = "v1.0.0"
	defer func() { Version = orgVer }()

	orgOpen := openBrowserFunc
	openBrowserFunc = func(string) bool { return false }
	defer func() { openBrowserFunc = orgOpen }()

	out := captureStdout(t, func() {
		if err := bugReport(newRootCmd(), nil); err != nil {
			t.Fatal(err)
		}
	})

	if !strings.Contains(out, "Please file a new issue") {
		t.Errorf("fallback output missing instructions:\n%s", out)
	}
	if !strings.Contains(out, "## jose version") {
		t.Errorf("fallback output missing template body:\n%s", out)
	}
}

// A bug report must name the version `jose version` names. bugReportBody used to
// resolve the version itself, and its resolver stopped at the Version global
// where resolveVersion falls back to the module build info — so a binary
// installed with `go install`, which sets no ldflags, filed reports saying
// "unknown" while `jose version` printed the real version.
//
// Not parallel: captureStdout redirects os.Stdout for the whole process.
func TestBugReportNamesTheVersionTheVersionCommandNames(t *testing.T) {
	orgOpen := openBrowserFunc
	openBrowserFunc = func(string) bool { return false }
	defer func() { openBrowserFunc = orgOpen }()

	orgVer := Version
	Version = ""
	defer func() { Version = orgVer }()

	out := captureStdout(t, func() {
		if err := bugReport(newRootCmd(), nil); err != nil {
			t.Fatal(err)
		}
	})

	want := "## jose version\n" + resolveVersion()
	if !strings.Contains(out, want) {
		t.Errorf("bug report does not name the version %q that `jose version` reports:\n%s", resolveVersion(), out)
	}
	if strings.Contains(out, "## jose version\nunknown") && resolveVersion() != "unknown" {
		t.Errorf("bug report fell back to \"unknown\" while resolveVersion() has %q", resolveVersion())
	}
}

func TestBugReportOpensBrowserWithEncodedURL(t *testing.T) {
	orgOpen := openBrowserFunc
	var got string
	openBrowserFunc = func(targetURL string) bool {
		got = targetURL
		return true
	}
	defer func() { openBrowserFunc = orgOpen }()

	if err := bugReport(newRootCmd(), nil); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "https://github.com/nao1215/jose/issues/new?") {
		t.Errorf("unexpected bug report URL: %s", got)
	}
}
