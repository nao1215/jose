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
	Name = "josex" //nolint
)

// getVersion return josex command version.
// Version global variable is set by ldflags.
func getVersion(cmd *cobra.Command, args []string) {
	version := "unknown"
	if Version != "" {
		version = Version
	} else if buildInfo, ok := debug.ReadBuildInfo(); ok {
		version = buildInfo.Main.Version
	}
	fmt.Printf("%s version %s (under MIT LICENSE)\n", Name, version)
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show " + Name + " command version information",
		Run:   getVersion,
	}
}
