package cmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/nao1215/gorky/file"
	"github.com/spf13/cobra"
)

func newCompletionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "completion",
		Short: "Create shell completion files (bash, fish, zsh)",
		Long:  `Create shell completion files (bash, fish, zsh)`,
		RunE:  completion,
	}
}

func completion(cmd *cobra.Command, args []string) error {
	return deployShellCompletionFileIfNeeded(cmd)
}

// isWindows check whether runtime is windosw or not.
func isWindows() bool {
	return runtime.GOOS == "windows"
}

// deployShellCompletionFileIfNeeded creates the shell completion file.
// If the file with the same contents already exists, it is not created.
func deployShellCompletionFileIfNeeded(cmd *cobra.Command) error {
	if isWindows() {
		fmt.Println("not support windows")
		return nil
	}
	makeBashCompletionFileIfNeeded(cmd)
	makeFishCompletionFileIfNeeded(cmd)
	makeZshCompletionFileIfNeeded(cmd)

	return nil
}

func makeBashCompletionFileIfNeeded(cmd *cobra.Command) error {
	if existSameBashCompletionFile(cmd) {
		return nil
	}

	path := bashCompletionFilePath()
	bashCompletion := new(bytes.Buffer)
	if err := cmd.GenBashCompletion(bashCompletion); err != nil {
		return fmt.Errorf("can not generate bash completion content: %w", err)
	}

	if !file.IsDir(path) {
		if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
			return fmt.Errorf("can not create bash-completion file: %w", err)
		}
	}
	fp, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("can not open .bash_completion: %w", err)
	}

	if _, err := fp.WriteString(bashCompletion.String()); err != nil {
		return fmt.Errorf("can not write .bash_completion %w", err)
	}

	if err := fp.Close(); err != nil {
		return fmt.Errorf("can not close .bash_completion %w", err)
	}

	fmt.Printf("created %s\n", path)

	return nil
}

func makeFishCompletionFileIfNeeded(cmd *cobra.Command) error {
	if isSameFishCompletionFile(cmd) {
		return nil
	}

	path := fishCompletionFilePath()
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return fmt.Errorf("can not create fish-completion file: %w", err)
	}

	if err := cmd.GenFishCompletionFile(path, false); err != nil {
		return fmt.Errorf("can not create fish-completion file: %w", err)
	}

	fmt.Printf("created %s\n", path)

	return nil
}

func makeZshCompletionFileIfNeeded(cmd *cobra.Command) error {
	if isSameZshCompletionFile(cmd) {
		return nil
	}

	path := zshCompletionFilePath()
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return fmt.Errorf("can not create zsh-completion file: %w", err)
	}

	if err := cmd.GenZshCompletionFile(path); err != nil {
		return fmt.Errorf("can not create zsh-completion file: %w", err)
	}

	if err := appendFpathAtZshrcIfNeeded(); err != nil {
		return err
	}

	fmt.Printf("created %s\n", path)

	return nil
}

func appendFpathAtZshrcIfNeeded() error {
	const zshFpath = `
# setting for golling command (auto generate)
fpath=(~/.zsh/completion $fpath)
autoload -Uz compinit && compinit -i
`
	zshrcPath := zshrcPath()
	if !file.IsFile(zshrcPath) {
		fp, err := os.OpenFile(zshrcPath, os.O_RDWR|os.O_CREATE, 0600)
		if err != nil {
			return fmt.Errorf("can not open .zshrc: %w", err)
		}

		if _, err := fp.WriteString(zshFpath); err != nil {
			return fmt.Errorf("can not write zsh $fpath in .zshrc: %w", err)
		}

		if err := fp.Close(); err != nil {
			return fmt.Errorf("can not close .zshrc: %w", err)
		}
		return nil
	}

	zshrc, err := os.ReadFile(zshrcPath)
	if err != nil {
		return fmt.Errorf("can not read .zshrc: %w", err)
	}

	if strings.Contains(string(zshrc), zshFpath) {
		return nil
	}

	fp, err := os.OpenFile(zshrcPath, os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("can not open .zshrc: %w", err)
	}

	if _, err := fp.WriteString(zshFpath); err != nil {
		return fmt.Errorf("can not write zsh $fpath in .zshrc: %w", err)
	}

	if err := fp.Close(); err != nil {
		return fmt.Errorf("can not close .zshrc: %w", err)
	}
	return nil
}

func existSameBashCompletionFile(cmd *cobra.Command) bool {
	if !file.IsFile(bashCompletionFilePath()) {
		return false
	}
	return hasSameBashCompletionContent(cmd)
}

func hasSameBashCompletionContent(cmd *cobra.Command) bool {
	bashCompletionFileInLocal, err := os.ReadFile(bashCompletionFilePath())
	if err != nil {
		fmt.Printf("can not read .bash_completion: %s\n", err.Error())
		return false
	}

	currentBashCompletion := new(bytes.Buffer)
	if err := cmd.GenBashCompletion(currentBashCompletion); err != nil {
		return false
	}
	if !strings.Contains(string(bashCompletionFileInLocal), currentBashCompletion.String()) {
		return false
	}
	return true
}

func isSameFishCompletionFile(cmd *cobra.Command) bool {
	path := fishCompletionFilePath()
	if !file.IsFile(path) {
		return false
	}

	currentFishCompletion := new(bytes.Buffer)
	if err := cmd.GenFishCompletion(currentFishCompletion, false); err != nil {
		return false
	}

	fishCompletionInLocal, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	if !bytes.Equal(currentFishCompletion.Bytes(), fishCompletionInLocal) {
		return false
	}
	return true
}

func isSameZshCompletionFile(cmd *cobra.Command) bool {
	path := zshCompletionFilePath()
	if !file.IsFile(path) {
		return false
	}

	currentZshCompletion := new(bytes.Buffer)
	if err := cmd.GenZshCompletion(currentZshCompletion); err != nil {
		return false
	}

	zshCompletionInLocal, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	if !bytes.Equal(currentZshCompletion.Bytes(), zshCompletionInLocal) {
		return false
	}
	return true
}

// bashCompletionFilePath return bash-completion file path.
func bashCompletionFilePath() string {
	return filepath.Join(os.Getenv("HOME"), ".bash_completion.d", Name)
}

// fishCompletionFilePath return fish-completion file path.
func fishCompletionFilePath() string {
	return filepath.Join(os.Getenv("HOME"), ".config", "fish", "completions", Name+".fish")
}

// zshCompletionFilePath return zsh-completion file path.
func zshCompletionFilePath() string {
	return filepath.Join(os.Getenv("HOME"), ".zsh", "completion", "_"+Name)
}

// zshrcPath return .zshrc path.
func zshrcPath() string {
	return filepath.Join(os.Getenv("HOME"), ".zshrc")
}
