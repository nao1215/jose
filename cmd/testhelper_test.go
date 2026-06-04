package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

// genKey generates a JWK with the given parameters and writes it to a file in a
// temporary directory, returning the file path. It fails the test on error.
func genKey(t testing.TB, keyType, curve string, size int, format string, public bool) string {
	t.Helper()

	dir := t.TempDir()
	ext := "json"
	if format == "pem" {
		ext = "pem"
	}
	path := filepath.Join(dir, "key."+ext)

	g := &jwkGenerater{
		Curve:        curve,
		KeyType:      keyType,
		KeySize:      size,
		OutputFormat: format,
		Output:       path,
		PublicKey:    public,
		KeySet:       jwk.NewSet(),
	}
	if err := g.valid(); err != nil {
		t.Fatalf("genKey valid(%s/%s): %v", keyType, curve, err)
	}
	if err := g.generate(); err != nil {
		t.Fatalf("genKey generate(%s/%s): %v", keyType, curve, err)
	}
	return path
}

// genKeyPublicOf reads a private JWK file and writes the public JWK derived
// from it to a new file, returning the path.
func genKeyPublicOf(t testing.TB, privPath string) string {
	t.Helper()
	set, err := getKeyFile(privPath, "json")
	if err != nil {
		t.Fatal(err)
	}
	key, _ := set.Key(0)
	pub, err := jwk.PublicKeyOf(key)
	if err != nil {
		t.Fatal(err)
	}
	buf, err := json.MarshalIndent(pub, "", "    ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "pub.json")
	if err := os.WriteFile(path, buf, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// octKeyFileWithKid writes a symmetric (oct) JWK carrying both an "alg" and a
// "kid", which match-kid verification requires, and returns the path.
func octKeyFileWithKid(t testing.TB, alg, kid string) string {
	t.Helper()
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	key, err := jwk.Import[jwk.Key](raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := key.Set(jwk.AlgorithmKey, alg); err != nil {
		t.Fatal(err)
	}
	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatal(err)
	}
	buf, err := json.MarshalIndent(key, "", "    ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "oct.json")
	if err := os.WriteFile(path, buf, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeFile writes content to a file in a temporary directory and returns its
// path.
func writeFile(t testing.TB, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// captureStdout runs fn while capturing everything written to os.Stdout and
// returns it as a string.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	backup := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = backup }()

	fn()

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}
