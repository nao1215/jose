package cmd

import (
	"testing"

	"github.com/nao1215/gorky/file"
)

func TestCompletion(t *testing.T) { //nolint
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	t.Run("generate completion file", func(t *testing.T) {
		t.Parallel()
		if isWindows() {
			return
		}

		cmd := newCompletionCmd()
		if err := completion(cmd, nil); err != nil {
			t.Fatal(err)
		}

		if !file.IsFile(fishCompletionFilePath()) {
			t.Errorf("failed to create %s", fishCompletionFilePath())
		}

		if !file.IsFile(bashCompletionFilePath()) {
			t.Errorf("failed to create %s", bashCompletionFilePath())
		}

		if !file.IsFile(zshCompletionFilePath()) {
			t.Errorf("failed to create %s", zshCompletionFilePath())
		}
	})

	t.Run("update completion file", func(t *testing.T) {
		t.Parallel()
		if isWindows() {
			return
		}

		cmd := newRootCmd()
		if err := completion(cmd, nil); err != nil {
			t.Fatal(err)
		}

		if !file.IsFile(fishCompletionFilePath()) {
			t.Errorf("failed to create %s", fishCompletionFilePath())
		}

		if !file.IsFile(bashCompletionFilePath()) {
			t.Errorf("failed to create %s", bashCompletionFilePath())
		}

		if !file.IsFile(zshCompletionFilePath()) {
			t.Errorf("failed to create %s", zshCompletionFilePath())
		}
	})
}
