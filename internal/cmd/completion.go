package cmd

import (
	"github.com/spf13/cobra"
)

func newCompletionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish]",
		Short: "Output shell completion script to stdout",
		Long: `Output a shell completion script to stdout.

The command only writes to stdout; it never edits your shell configuration.
Redirect the output to the location your shell loads completions from.

Bash:
  jose completion bash > /etc/bash_completion.d/jose

Zsh:
  jose completion zsh > "${fpath[1]}/_jose"

Fish:
  jose completion fish > ~/.config/fish/completions/jose.fish`,
		Args:      cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		ValidArgs: []string{"bash", "zsh", "fish"},
		RunE:      runCompletion,
	}
	return cmd
}

func runCompletion(cmd *cobra.Command, args []string) error {
	root := cmd.Root()
	switch args[0] {
	case "bash":
		return root.GenBashCompletionV2(cmd.OutOrStdout(), true)
	case "zsh":
		return root.GenZshCompletion(cmd.OutOrStdout())
	case "fish":
		return root.GenFishCompletion(cmd.OutOrStdout(), true)
	default:
		return wrap(ErrUnsupportedShell, args[0])
	}
}
