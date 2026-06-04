package cmd

import (
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/nao1215/gorky/file"
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

// stdinIsPipe reports whether standard input is connected to a pipe or a
// redirection rather than an interactive terminal. It lets jose read piped
// input ("echo ... | jose ...") even when no file argument is given. It is a
// variable so tests can simulate a pipe.
var stdinIsPipe = func() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) == 0
}

func openInputFile(path string) (io.ReadCloser, error) {
	if path == "" {
		// No file was given. Read from stdin when input is piped so that
		// "echo ... | jose ..." works without an explicit "-".
		if stdinIsPipe() {
			return io.NopCloser(os.Stdin), nil
		}
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

// readInput reads all bytes from the input named by path. path may be a file
// path, "-" for stdin, or empty to read piped stdin. It is the payload/message
// reader shared by sign, encrypt, and decrypt.
func readInput(path string) ([]byte, error) {
	src, err := openInputFile(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = src.Close()
	}()

	data, err := io.ReadAll(src)
	if err != nil {
		return nil, wrap(ErrReadFile, err.Error())
	}
	return data, nil
}

// looksLikeCompactJWS reports whether s has the shape of a compact JWS:
// three base64url segments separated by dots, where the protected header
// (the first segment) base64url-decodes to valid JSON. This lets jose tell an
// inline token apart from a mistyped file name like "does-not-exist.jws".
func looksLikeCompactJWS(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	// The header and payload must be present; an unsecured JWS could have an
	// empty signature, so only the first two segments are required.
	if parts[0] == "" || parts[1] == "" {
		return false
	}
	for _, p := range parts {
		if !isBase64URL(p) {
			return false
		}
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	return json.Valid(header)
}

// isBase64URL reports whether s contains only base64url characters (the
// unpadded alphabet used by compact JOSE serializations). An empty string is
// allowed so an empty signature segment passes.
func isBase64URL(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}

// readCompactJWS resolves the bytes of a JWS message from a positional
// argument. The argument may be a file path, "-" for stdin, or an inline
// compact JWS token; when arg is empty and stdin is piped it reads stdin. A
// value that is neither an existing file nor a token-shaped string is treated
// as a file path so that a typo reports "failed to open file" instead of a
// confusing parse error.
func readCompactJWS(arg string) ([]byte, error) {
	switch {
	case arg == "" || arg == "-":
		// stdin (piped or "-"); fall through to openInputFile.
	case file.IsFile(arg):
		// existing file; fall through to openInputFile.
	case looksLikeCompactJWS(arg):
		return []byte(arg), nil
		// default: not a file and not token-shaped; openInputFile reports the
		// real file-open error below.
	}
	return readInput(arg)
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
	return []string{
		elliptic.P256().Params().Name,
		elliptic.P384().Params().Name,
		elliptic.P521().Params().Name,
	}
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
	var keyoptions []jwk.ParseOption
	switch format {
	case "json":
	case "pem":
		// v4 renamed WithPEM to WithX509 for PEM-framed X.509 input.
		keyoptions = append(keyoptions, jwk.WithX509(true))
	default:
		return nil, wrap(ErrInvalidKeyFormat, "format is "+format)
	}

	data, err := os.ReadFile(keyFile) //nolint:gosec // key path is supplied by the user on purpose
	if err != nil {
		return nil, wrap(ErrOpenFile, err.Error())
	}

	keySet, err := jwk.Parse(data, keyoptions...)
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
