package cmd

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/spf13/cobra"
)

var (
	// Version value is set by ldflags.
	//
	// A test that writes to this must not call t.Parallel: newRootCmd reads it
	// through resolveVersion, so a write from one parallel test races every
	// other parallel test that builds a command. Prefer passing the version to
	// the function under test, the way bugReportBody takes it.
	Version string
	// Name is cli command name
	Name = "jose"
)

// resolveVersion returns the jose version string, preferring the value set by
// ldflags and falling back to the module build info, then to "unknown".
func resolveVersion() string {
	if Version != "" {
		return Version
	}
	if buildInfo, ok := debug.ReadBuildInfo(); ok && buildInfo.Main.Version != "" {
		return buildInfo.Main.Version
	}
	return "unknown"
}

// versionLine returns the single line printed by both "jose version" and
// "jose --version" so the two never drift apart.
func versionLine() string {
	return fmt.Sprintf("%s version %s (under MIT LICENSE)", Name, resolveVersion())
}

// getVersion return jose command version.
// Version global variable is set by ldflags.
func getVersion(_ *cobra.Command, _ []string) error {
	return writeOutput(os.Stdout, []byte(versionLine()+"\n"))
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show " + Name + " command version information",
		RunE:  getVersion,
	}
}
