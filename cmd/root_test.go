package cmd

import (
	"bytes"
	"os"
	"testing"
)

func TestVersion(t *testing.T) {
	t.Run("Execute version subcommand", func(t *testing.T) {
		os.Args = []string{
			"jose",
			"version",
		}

		Version = "v1.0.0"
		defer func() {
			Version = ""
		}()

		wantExitCode := 0
		wantStdOut := "jose version v1.0.0 (under MIT LICENSE)"
		gotStdOut, gotExitCode := getStdout(t, Execute)
		if wantStdOut != gotStdOut {
			t.Errorf("mismatch want=%s, got=%s", wantStdOut, gotStdOut)
		}

		if wantExitCode != gotExitCode {
			t.Errorf("mismatch want=%d, got=%d", wantExitCode, gotExitCode)
		}
	})
}

type executeFn func() int

func getStdout(t *testing.T, fn executeFn) (string, int) {
	t.Helper()
	backup := os.Stdout
	defer func() {
		os.Stdout = backup
	}()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal()
	}
	os.Stdout = w

	exitCode := fn() // test target

	if err := w.Close(); err != nil {
		t.Fatal()
	}

	var buffer bytes.Buffer
	if _, err := buffer.ReadFrom(r); err != nil {
		t.Fatalf("fail read buf: %v", err)
	}
	s := buffer.String()

	return s[:len(s)-1], exitCode
}
