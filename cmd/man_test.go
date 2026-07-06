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
