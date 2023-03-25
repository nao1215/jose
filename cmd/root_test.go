package cmd

import (
	"bytes"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
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

func TestExecute(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		wantExitCode int
		wantStdOut   string
	}{
		{
			name:         "get key-types",
			args:         []string{"jose", "jwa", "--key-type"},
			wantExitCode: 0,
			wantStdOut:   "EC\nOKP\nRSA\noct",
		},
		{
			name:         "get elliptic curve types",
			args:         []string{"jose", "jwa", "--elliptic-curve"},
			wantExitCode: 0,
			wantStdOut:   "Ed25519\nEd448\nP-256\nP-384\nP-521\nX25519\nX448",
		},
		{
			name:         "get key encryption algorithms",
			args:         []string{"jose", "jwa", "--key-encryption"},
			wantExitCode: 0,
			wantStdOut:   "A128GCMKW\nA128KW\nA192GCMKW\nA192KW\nA256GCMKW\nA256KW\nECDH-ES\nECDH-ES+A128KW\nECDH-ES+A192KW\nECDH-ES+A256KW\nPBES2-HS256+A128KW\nPBES2-HS384+A192KW\nPBES2-HS512+A256KW\nRSA-OAEP\nRSA-OAEP-256\nRSA1_5\ndir",
		},
		{
			name:         "get content encryption algorithms",
			args:         []string{"jose", "jwa", "--content-encryption"},
			wantExitCode: 0,
			wantStdOut:   "A128CBC-HS256\nA128GCM\nA192CBC-HS384\nA192GCM\nA256CBC-HS512\nA256GCM",
		},
		{
			name:         "get signature algorithms",
			args:         []string{"jose", "jwa", "--signature"},
			wantExitCode: 0,
			wantStdOut:   "ES256\nES256K\nES384\nES512\nEdDSA\nHS256\nHS384\nHS512\nPS256\nPS384\nPS512\nRS256\nRS384\nRS512\nnone",
		},
		{
			name:         "set no options",
			args:         []string{"jose", "jwa"},
			wantExitCode: 1,
			wantStdOut:   "", // not print stdout, print stderr
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Args = tt.args
			gotStdOut, gotExitCode := getStdout(t, Execute)
			if tt.wantExitCode != gotExitCode {
				t.Errorf("exit code mismatch: want=%d, got=%d", tt.wantExitCode, gotExitCode)
			}

			if diff := cmp.Diff(tt.wantStdOut, gotStdOut); diff != "" {
				t.Errorf("value is mismatch (-want +got):\n%s", diff)
			}
		})
	}
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
