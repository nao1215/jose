// Package main is the jose command entrypoint.
package main

import (
	"os"
	"testing"
)

func Test_main(t *testing.T) {
	t.Run("Execute version subcommand", func(t *testing.T) {
		exitCode := -1
		oldOsExit := osExit
		osExit = func(code int) {
			exitCode = code
		}
		defer func() {
			osExit = oldOsExit
		}()

		os.Args = []string{
			"jose",
			"version",
		}
		main() // Run test

		if exitCode != 0 {
			t.Errorf("mismatch exit code: want=0, got=%d", exitCode)
		}
	})

	t.Run("Execution of a non-existent subcommand", func(t *testing.T) {
		exitCode := -1
		oldOsExit := osExit
		osExit = func(code int) {
			exitCode = code
		}
		defer func() {
			osExit = oldOsExit
		}()

		os.Args = []string{
			"jose",
			"non-existent",
		}
		main() // Run test

		if exitCode != 1 {
			t.Errorf("mismatch exit code: want=1, got=%d", exitCode)
		}
	})
}
