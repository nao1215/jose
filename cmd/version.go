package cmd

import (
	"fmt"
	"runtime/debug"

	"github.com/spf13/cobra"
)

var (
	// Version value is set by ldflags
	Version string //nolint
	// Name is cli command name
	Name = "jose" //nolint
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
func getVersion(_ *cobra.Command, _ []string) {
	fmt.Println(versionLine())
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show " + Name + " command version information",
		Run:   getVersion,
	}
}
