package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
)

// linesOf splits writer output into trimmed, non-empty lines.
func linesOf(s string) []string {
	out := []string{}
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func hasLine(lines []string, want string) bool {
	for _, l := range lines {
		if l == want {
			return true
		}
	}
	return false
}

// TestJWAOnlyListsSupportedSignatures verifies that "jose jwa --signature"
// excludes algorithms jose rejects (Ed25519, none) while keeping EdDSA, and
// that every printed value is actually accepted by jws sign.
func TestJWAOnlyListsSupportedSignatures(t *testing.T) {
	t.Parallel()

	j := &jsonWebAlhorithm{signature: true}
	var buf bytes.Buffer
	j.writeSignatureAlgorithms(&buf)
	lines := linesOf(buf.String())

	for _, bad := range []string{"Ed25519", "none"} {
		if hasLine(lines, bad) {
			t.Errorf("jwa --signature must not list %q", bad)
		}
	}
	if !hasLine(lines, "EdDSA") {
		t.Errorf("jwa --signature must list EdDSA, got %v", lines)
	}

	// Every printed value must be a valid algorithm for jws sign.
	for _, alg := range lines {
		s := &jwsSigner{Algorithm: alg, Key: "k.json", KeyFormat: "json"}
		if err := s.valid(); err != nil {
			t.Errorf("jwa printed %q but jws sign rejects it: %v", alg, err)
		}
		if _, ok := jwa.LookupSignatureAlgorithm(alg); !ok {
			t.Errorf("jwa printed %q but jwx does not know it", alg)
		}
	}
}

// TestJWAOnlyListsSupportedCurves verifies that X448 is not advertised and that
// the supported curves are present.
func TestJWAOnlyListsSupportedCurves(t *testing.T) {
	t.Parallel()

	j := &jsonWebAlhorithm{elipticCurve: true}
	var buf bytes.Buffer
	j.writeEllipticCurveAlgorithms(&buf)
	lines := linesOf(buf.String())

	if hasLine(lines, "X448") {
		t.Errorf("jwa --elliptic-curve must not list X448")
	}
	for _, want := range []string{"P-256", "P-384", "P-521", "Ed25519", "X25519"} {
		if !hasLine(lines, want) {
			t.Errorf("jwa --elliptic-curve must list %q, got %v", want, lines)
		}
	}
}

// TestJWAOnlyListsSupportedKeyEncryption verifies that algorithms jose rejects
// (RSA-OAEP-384, the HPKE family) are not advertised and that each printed
// value is accepted by jwe encrypt.
func TestJWAOnlyListsSupportedKeyEncryption(t *testing.T) {
	t.Parallel()

	j := &jsonWebAlhorithm{keyEncryption: true}
	var buf bytes.Buffer
	j.writeKeyEncryptionAlgorithms(&buf)
	lines := linesOf(buf.String())

	for _, bad := range []string{"RSA-OAEP-384", "RSA-OAEP-512", "HPKE-0-KE"} {
		if hasLine(lines, bad) {
			t.Errorf("jwa --key-encryption must not list %q", bad)
		}
	}
	if !hasLine(lines, "RSA-OAEP") {
		t.Errorf("jwa --key-encryption must list RSA-OAEP, got %v", lines)
	}

	for _, alg := range lines {
		e := &jweEncrypter{ContentEncryption: "A256GCM", Key: "k.json", KeyEncryption: alg, KeyFormat: "json"}
		if err := e.valid(); err != nil {
			t.Errorf("jwa printed %q but jwe encrypt rejects it: %v", alg, err)
		}
	}
}

// TestJWAOnlyListsSupportedKeyTypes verifies that the AKP type advertised by
// jwx is filtered out.
func TestJWAOnlyListsSupportedKeyTypes(t *testing.T) {
	t.Parallel()

	j := &jsonWebAlhorithm{keyType: true}
	var buf bytes.Buffer
	j.writeKeyTypes(&buf)
	lines := linesOf(buf.String())

	if hasLine(lines, "AKP") {
		t.Errorf("jwa --key-type must not list AKP")
	}
	for _, want := range []string{"RSA", "EC", "OKP", "oct"} {
		if !hasLine(lines, want) {
			t.Errorf("jwa --key-type must list %q, got %v", want, lines)
		}
	}
}

// TestFilterSupported checks the intersection helper preserves the order of the
// advertised list and drops unsupported entries.
func TestFilterSupported(t *testing.T) {
	t.Parallel()

	got := filterSupported([]string{"a", "b", "c", "d"}, []string{"d", "b"})
	want := []string{"b", "d"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("filterSupported = %v, want %v", got, want)
	}
}
