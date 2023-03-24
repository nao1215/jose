//go:build !int

package cmd

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestBugReport(t *testing.T) {
	t.Run("Check bug-report --help", func(t *testing.T) {
		t.Parallel()

		b := bytes.NewBufferString("")

		copyRootCmd := newRootCmd()

		copyRootCmd.SetOut(b)
		copyRootCmd.SetArgs([]string{"bug-report", "--help"})

		if err := copyRootCmd.Execute(); err != nil {
			t.Fatal(err)
		}
		gotBytes, err := io.ReadAll(b)
		if err != nil {
			t.Fatal(err)
		}
		gotBytes = bytes.ReplaceAll(gotBytes, []byte("\r\n"), []byte("\n"))

		wantBytes, err := os.ReadFile(filepath.Join("testdata", "bug_report", "bug_report.txt"))
		if err != nil {
			t.Fatal(err)
		}
		wantBytes = bytes.ReplaceAll(wantBytes, []byte("\r\n"), []byte("\n"))

		if diff := cmp.Diff(strings.TrimSpace(string(gotBytes)), strings.TrimSpace(string(wantBytes))); diff != "" {
			t.Errorf("value is mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("open bug report", func(t *testing.T) {
		orgVer := Version
		Version = "v1.0.0"
		defer func() {
			Version = orgVer
		}()

		var got string
		openBrowserFunc = func(targetURL string) bool {
			got = targetURL
			return true
		}

		cmd := newRootCmd()
		if err := bugReport(cmd, []string{}); err != nil {
			t.Fatal(err)
		}

		want := "https://github.com/nao1215/jose/issues/new?title=[Bug Report] Title&body=%23%23+jose+version%2A%2A%0Av1.0.0%0A%0A%23%23+Description+%28About+the+problem%29%0AA+clear+description+of+the+bug+encountered.%0A%0A%23%23+Steps+to+reproduce%0ASteps+to+reproduce+the+bug.%0A%0A%23%23+Expected+behavior%0AExpected+behavior.%0A%0A%23%23+Additional+details%2A%2A%0AAny+other+useful+data+to+share.%0A"
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})
}
