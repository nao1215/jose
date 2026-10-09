package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestManInstallsPagesToConfiguredDir(t *testing.T) {
	// Redirect the install directory so `man` runs without root or system writes.
	orig := manInstallDir
	dst := t.TempDir()
	manInstallDir = dst
	defer func() { manInstallDir = orig }()

	if err := man(nil, nil); err != nil {
		t.Fatalf("man() failed: %v", err)
	}
	pages, err := filepath.Glob(filepath.Join(dst, "*.1.gz"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pages) == 0 {
		t.Error("man() installed no pages")
	}
}

func TestGenerateManpagesReportsWriteError(t *testing.T) {
	t.Parallel()
	// A destination directory that does not exist makes the copy step fail when
	// it tries to create each page there.
	dst := filepath.Join(t.TempDir(), "no-such-dir")
	if err := generateManpages(dst); err == nil {
		t.Error("generateManpages should fail when the destination does not exist")
	}
}

func TestGenerateManpages(t *testing.T) {
	t.Parallel()

	t.Run("Generate man pages", func(t *testing.T) {
		dst, err := os.MkdirTemp("", "test")
		if err != nil {
			t.Fatalf("Failed to create temp dir: %v", err)
		}
		defer func() {
			if removeErr := os.RemoveAll(dst); removeErr != nil {
				t.Fatal(removeErr)
			}
		}()

		if err := generateManpages(dst); err != nil {
			t.Fatalf("generateManpages() failed: %v", err)
		}

		manFiles, err := filepath.Glob(filepath.Join(dst, "*.1.gz"))
		if err != nil {
			t.Errorf("Failed to glob man files: %v", err)
		}
		if len(manFiles) == 0 {
			t.Error("No man files found")
		}
	})
}

func TestGenerateManpagesReportsTempDirError(t *testing.T) {
	// The pages are rendered in a temporary directory first; when none can be
	// made, nothing is installed and the error is returned.
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "no-such-dir"))
	dst := t.TempDir()
	if err := generateManpages(dst); err == nil {
		t.Error("generateManpages should fail when no temporary directory can be made")
	}
	pages, err := filepath.Glob(filepath.Join(dst, "*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pages) != 0 {
		t.Errorf("no page should be installed, got %v", pages)
	}
}

func TestCopyManpagesReportsSourceErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		source func(t *testing.T) string
	}{
		{
			name:   "missing source page fails to open",
			source: func(t *testing.T) string { return filepath.Join(t.TempDir(), "jose.1") },
		},
		{
			name:   "directory as source page fails to copy",
			source: func(t *testing.T) string { return t.TempDir() },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := copyManpages([]string{tt.source(t)}, t.TempDir()); err == nil {
				t.Error("copyManpages should fail")
			}
		})
	}
}
