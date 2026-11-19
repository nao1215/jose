package cmd

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestCompletionGeneratesScriptToStdout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		shell       string
		wantInclude string
	}{
		{shell: "bash", wantInclude: "bash completion"},
		{shell: "zsh", wantInclude: "#compdef"},
		{shell: "fish", wantInclude: "fish"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.shell, func(t *testing.T) {
			t.Parallel()

			root := newRootCmd()
			var buf bytes.Buffer
			root.SetOut(&buf)
			root.SetArgs([]string{"completion", tt.shell})
			if err := root.Execute(); err != nil {
				t.Fatalf("completion %s: %v", tt.shell, err)
			}
			if !strings.Contains(strings.ToLower(buf.String()), strings.ToLower(tt.wantInclude)) {
				t.Errorf("completion %s output missing %q:\n%s", tt.shell, tt.wantInclude, buf.String())
			}
		})
	}
}

func TestCompletionDoesNotTouchHomeFiles(t *testing.T) {
	// The completion command must be non-destructive: it must not create files
	// under HOME or edit .zshrc the way the old implementation did.
	home := t.TempDir()
	t.Setenv("HOME", home)

	root := newRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetArgs([]string{"completion", "zsh"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("completion wrote to HOME: %v", names)
	}
}

func TestCompletionRejectsUnknownShell(t *testing.T) {
	t.Parallel()

	root := newRootCmd()
	root.SetArgs([]string{"completion", "powershell"})
	root.SetOut(new(bytes.Buffer))
	root.SetErr(new(bytes.Buffer))
	if err := root.Execute(); err == nil {
		t.Error("expected error for unknown shell, got nil")
	}
}

func TestCompletionRequiresShellArgument(t *testing.T) {
	t.Parallel()

	root := newRootCmd()
	root.SetArgs([]string{"completion"})
	root.SetOut(new(bytes.Buffer))
	root.SetErr(new(bytes.Buffer))
	if err := root.Execute(); err == nil {
		t.Error("expected error when no shell argument given, got nil")
	}
}

func TestRunCompletionUnsupportedShell(t *testing.T) {
	t.Parallel()

	// Directly drive runCompletion with a shell that passed arg validation in
	// theory, to cover the defensive default branch.
	cmd := newCompletionCmd()
	cmd.SetOut(new(bytes.Buffer))
	err := runCompletion(cmd, []string{"powershell"})
	if !errors.Is(err, ErrUnsupportedShell) {
		t.Errorf("want ErrUnsupportedShell, got %v", err)
	}
}
