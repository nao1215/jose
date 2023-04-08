// Package cmd is a package that contains subcommands for the jose CLI command.
package cmd

import (
	"github.com/charmbracelet/log"
	"github.com/spf13/cobra"
)

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "jose",
		Short: "jose is toolset for JSON Object Signing and Encryption (JOSE).",
	}

	cmd.CompletionOptions.DisableDefaultCmd = true
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	cmd.AddCommand(newVersionCmd())
	cmd.AddCommand(newCompletionCmd())
	cmd.AddCommand(newJWKCmd())
	cmd.AddCommand(newBugReportCmd())
	cmd.AddCommand(newManCmd())
	cmd.AddCommand(newJWACmd())
	cmd.AddCommand(newJWECmd())
	cmd.AddCommand(newJWSCmd())

	return cmd
}

// Execute run leadtime process.
func Execute() int {
	rootCmd := newRootCmd()

	if err := rootCmd.Execute(); err != nil {
		log.Error(err)
		return 1
	}
	return 0
}
