package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

const (
	defaultKeySize = 2048
)

func writeJSON(w io.Writer, v interface{}) error {
	buf, err := json.MarshalIndent(v, "", "    ")
	if err != nil {
		return wrap(ErrSerializeJOSN, err.Error())
	}

	if _, err := w.Write(append(buf, '\n')); err != nil {
		return wrap(ErrWriteJSON, err.Error())
	}
	return nil
}

func openInputFile(path string) (io.ReadCloser, error) {
	if path == "" {
		return nil, ErrRequireFileName
	}

	if path == "-" {
		return io.NopCloser(os.Stdin), nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, wrap(ErrOpenFile, err.Error())
	}
	return f, nil
}

type dummyWriteCloser struct {
	io.Writer
}

func (*dummyWriteCloser) Close() error {
	return nil
}

func openOutputFile(path string) (io.WriteCloser, error) {
	var output io.WriteCloser
	switch path {
	case "-":
		output = &dummyWriteCloser{os.Stdout}
	case "":
		return nil, ErrRequireFileName
	default:
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return nil, fmt.Errorf(`%w: %s`, ErrCreateFile, err.Error())
		}
		output = f
	}
	return output, nil
}

// availableCurves returns the elliptic curves usable for EC keys
// (P-256/P-384/P-521).
func availableCurves() []string {
	curves := []string{}
	for _, v := range jwk.AvailableCurves() {
		curves = append(curves, v.Params().Name)
	}
	return curves
}

// availableOKPCurves returns the curves jose can actually generate for OKP
// keys. The jwx library advertises Ed448/X448 as constants, but the Go
// standard library has no generator for them, so jose only supports
// Ed25519 and X25519.
func availableOKPCurves() []string {
	return []string{"Ed25519", "X25519"}
}

// contains reports whether s is present in list.
func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func getKeyFile(keyFile, format string) (jwk.Set, error) {
	var keyoptions []jwk.ReadFileOption
	switch format {
	case "json":
	case "pem":
		keyoptions = append(keyoptions, jwk.WithPEM(true))
	default:
		return nil, wrap(ErrInvalidKeyFormat, "format is "+format)
	}

	keySet, err := jwk.ReadFile(keyFile, keyoptions...)
	if err != nil {
		return nil, wrap(ErrParseKey, err.Error())
	}
	return keySet, nil
}

func chop(s string) string {
	s = strings.TrimRight(s, "\n")
	if strings.HasSuffix(s, "\r") {
		s = strings.TrimRight(s, "\r")
	}
	return s
}
