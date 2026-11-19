// Package main is the jose command entrypoint.
package main

import (
	"os"

	"github.com/nao1215/jose/internal/cmd"
)

// osExit is wrapper for  os.Exit(). It's for unit test.
var osExit = os.Exit

func main() {
	osExit(cmd.Execute())
}
