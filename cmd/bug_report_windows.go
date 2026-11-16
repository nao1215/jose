//go:build windows

// Package cmd is a package that contains subcommands for the jose CLI command.
package cmd

import (
	"os/exec"
)

func openBrowser(targetURL string) bool {
	// rundll32 hands the URL to the default browser without cmd.exe parsing it.
	return exec.Command("rundll32", "url.dll,FileProtocolHandler", targetURL).Start() == nil // #nosec G204 -- targetURL is the issue URL bugReport builds
}
