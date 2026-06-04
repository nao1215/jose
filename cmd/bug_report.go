package cmd

import (
	"bytes"
	"fmt"
	"net/url"
	"runtime"

	"github.com/spf13/cobra"
)

func newBugReportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "bug-report",
		Short: "Open a pre-filled bug report in your browser",
		Long: `bug-report opens the default browser with a GitHub issue template that
already contains your jose version and runtime information (OS, architecture,
and Go version). If a browser cannot be opened, the template is printed to
stdout so you can paste it into a new issue by hand.`,
		RunE: bugReport,
	}
}

var openBrowserFunc = openBrowser //nolint

// version returns the jose version string, falling back to "unknown" when it
// was not set at build time.
func version() string {
	if Version != "" {
		return Version
	}
	return "unknown"
}

// bugReportBody builds the Markdown issue body, including the runtime details
// that make a report actionable.
func bugReportBody() string {
	var buf bytes.Buffer

	fmt.Fprintf(&buf, "## jose version\n%s\n\n", version())
	fmt.Fprintf(&buf, "## Environment\n- OS: %s\n- Architecture: %s\n- Go: %s\n\n",
		runtime.GOOS, runtime.GOARCH, runtime.Version())
	buf.WriteString("## Description (About the problem)\nA clear description of the bug encountered.\n\n")
	buf.WriteString("## Steps to reproduce\nSteps to reproduce the bug.\n\n")
	buf.WriteString("## Expected behavior\nExpected behavior.\n\n")
	buf.WriteString("## Additional details\nAny other useful data to share.\n")

	return buf.String()
}

func bugReport(_ *cobra.Command, _ []string) error {
	body := bugReportBody()
	target := "https://github.com/nao1215/jose/issues/new?title=[Bug Report] Title&body=" + url.QueryEscape(body)

	if !openBrowserFunc(target) {
		fmt.Print("Please file a new issue at https://github.com/nao1215/jose/issues/new using this template:\n\n")
		fmt.Print(body)
	}
	return nil
}
