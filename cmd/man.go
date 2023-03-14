package cmd

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

func newManCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "man",
		Short:   "Generate man-pages under /usr/share/man/man1 (need root privilege)",
		Long:    `Generate man-pages under /usr/share/man/man1 (need root privilege)`,
		Example: "  sudo jose man",
		RunE:    man,
	}
	return cmd
}

func man(cmd *cobra.Command, args []string) error { //nolint
	return generateManpages(filepath.Join("/", "usr", "share", "man", "man1"))
}

func generateManpages(dst string) error {
	now := time.Now()
	header := &doc.GenManHeader{
		Title:   `jose - CLI tool for JOSE (JSON Object Signing and Encryption)`,
		Section: "1",
		Date:    &now,
	}

	tmpDir, err := os.MkdirTemp("", "jose")
	if err != nil {
		return err
	}
	defer func() {
		if removeErr := os.RemoveAll(tmpDir); removeErr != nil {
			err = errors.Join(err, removeErr)
		}
	}()

	err = doc.GenManTree(newRootCmd(), header, tmpDir)
	if err != nil {
		return err
	}

	manFiles, err := filepath.Glob(filepath.Join(tmpDir, "*.1"))
	if err != nil {
		return err
	}

	return copyManpages(manFiles, dst)
}

func copyManpages(manFiles []string, dst string) error {
	dst = filepath.Clean(dst)

	for _, file := range manFiles {
		file = filepath.Clean(file)

		in, err := os.Open(file)
		if err != nil {
			return err
		}
		defer func() {
			if closeErr := in.Close(); closeErr != nil {
				err = errors.Join(err, closeErr)
			}
		}()

		out, err := os.Create(filepath.Join(dst, filepath.Base(file)+".gz"))
		if err != nil {
			return err
		}
		defer func() {
			if closeErr := out.Close(); closeErr != nil {
				err = errors.Join(err, closeErr)
			}
		}()

		gz := gzip.NewWriter(out)
		gz.Name = strings.TrimSuffix(filepath.Base(file), ".1")
		defer func() {
			if closeErr := gz.Close(); closeErr != nil {
				err = errors.Join(err, closeErr)
			}
		}()

		fmt.Println("Generate " + out.Name())
		_, err = io.Copy(gz, in)
		if err != nil {
			return err
		}
	}
	return nil
}
