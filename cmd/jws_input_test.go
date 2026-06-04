package cmd

import (
	"bytes"
	"errors"
	"testing"
)

// TestJWSVerifyAcceptsInlineToken reproduces the report that "jose jws verify"
// could not take a token string directly: passing the compact JWS as the
// positional argument must verify, not be treated as a file path.
func TestJWSVerifyAcceptsInlineToken(t *testing.T) {
	t.Parallel()

	keyPath := genKey(t, "EC", "P-256", 2048, "json", false)
	payloadPath := writeFile(t, "payload.txt", "inline token")
	token := signWith(t, keyPath, "ES256", payloadPath, "")

	v := &jwsVerifier{
		Algorithm:     "ES256",
		Key:           keyPath,
		KeyFormat:     "json",
		InputFilePath: token, // the token itself, not a file
		Output:        "-",
	}

	out := captureStdout(t, func() {
		if err := v.verify(); err != nil {
			t.Errorf("verify with inline token failed: %v", err)
		}
	})
	if out != "inline token" {
		t.Errorf("payload mismatch: %q", out)
	}
}

// TestJWSVerifyMissingFileReportsOpenError ensures a mistyped file name is
// reported as a missing file rather than a verify/parse error.
func TestJWSVerifyMissingFileReportsOpenError(t *testing.T) {
	t.Parallel()

	keyPath := genKey(t, "EC", "P-256", 2048, "json", false)
	v := &jwsVerifier{
		Algorithm:     "ES256",
		Key:           keyPath,
		KeyFormat:     "json",
		InputFilePath: "does-not-exist.jws",
		Output:        "-",
	}
	if err := v.verify(); !errors.Is(err, ErrOpenFile) {
		t.Errorf("expected ErrOpenFile, got %v", err)
	}
}

// TestJWSParseMissingFileReportsOpenError reproduces the report that "jose jws
// parse does-not-exist.jws" wrongly reported a compact-format parse failure.
// A non-token-shaped, non-existent argument must report a file-open error.
func TestJWSParseMissingFileReportsOpenError(t *testing.T) {
	t.Parallel()

	cmd := newJWSParseCmd()
	_, err := newJWSParser(cmd, []string{"does-not-exist.jws"})
	if !errors.Is(err, ErrOpenFile) {
		t.Errorf("expected ErrOpenFile, got %v", err)
	}
}

// TestJWSParseFromPipe verifies pipe support: a token on stdin with no argument
// is parsed.
func TestJWSParseFromPipe(t *testing.T) {
	withStdinPipe(t, sampleJWS)

	cmd := newJWSParseCmd()
	p, err := newJWSParser(cmd, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(p.jws, []byte(sampleJWS)) {
		t.Errorf("piped token not captured: %q", p.jws)
	}
}
