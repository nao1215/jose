package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runCLI sets os.Args and runs Execute, capturing stdout and the exit code.
func runCLI(t *testing.T, args ...string) (string, int) {
	t.Helper()
	os.Args = append([]string{"jose"}, args...)
	return getStdout(t, Execute)
}

func TestCLIJWKGenerateToStdout(t *testing.T) {
	out, code := runCLI(t, "jwk", "generate", "--type", "EC", "--curve", "P-256")
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(out, `"kty"`) || !strings.Contains(out, `"EC"`) {
		t.Errorf("unexpected jwk output: %s", out)
	}
}

func TestCLIJWKGenerateInvalidCurve(t *testing.T) {
	_, code := runCLI(t, "jwk", "generate", "--type", "OKP", "--curve", "X448")
	if code != 1 {
		t.Errorf("expected failure for X448, exit code = %d", code)
	}
}

func TestCLIJWSSignVerifyParseFlow(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ec.jwk")
	payloadPath := filepath.Join(dir, "payload.txt")
	jwsPath := filepath.Join(dir, "msg.jws")

	if err := os.WriteFile(payloadPath, []byte("Hello, World!"), 0600); err != nil {
		t.Fatal(err)
	}

	// generate
	if _, code := runCLI(t, "jwk", "generate", "--type", "EC", "--curve", "P-256", "--output", keyPath); code != 0 {
		t.Fatalf("generate exit = %d", code)
	}
	// sign
	if _, code := runCLI(t, "jws", "sign", "--algorithm", "ES256", "--key", keyPath, "--output", jwsPath, payloadPath); code != 0 {
		t.Fatalf("sign exit = %d", code)
	}
	// verify
	out, code := runCLI(t, "jws", "verify", "--algorithm", "ES256", "--key", keyPath, jwsPath)
	if code != 0 {
		t.Fatalf("verify exit = %d", code)
	}
	if out != "Hello, World!" {
		t.Errorf("verify payload = %q", out)
	}
	// parse payload
	out, code = runCLI(t, "jws", "parse", jwsPath)
	if code != 0 {
		t.Fatalf("parse exit = %d", code)
	}
	if out != "Hello, World!" {
		t.Errorf("parse payload = %q", out)
	}
	// parse --all
	out, code = runCLI(t, "jws", "parse", "--all", jwsPath)
	if code != 0 {
		t.Fatalf("parse --all exit = %d", code)
	}
	for _, want := range []string{"Payload:", "JWS:", "Signature 0:"} {
		if !strings.Contains(out, want) {
			t.Errorf("parse --all output missing %q:\n%s", want, out)
		}
	}
}

func TestCLIJWSSignMissingAlgorithm(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ec.jwk")
	payloadPath := filepath.Join(dir, "payload.txt")
	if err := os.WriteFile(payloadPath, []byte("hi"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, code := runCLI(t, "jwk", "generate", "--type", "EC", "--curve", "P-256", "--output", keyPath); code != 0 {
		t.Fatal("generate failed")
	}
	if _, code := runCLI(t, "jws", "sign", "--key", keyPath, payloadPath); code != 1 {
		t.Errorf("expected failure without algorithm, exit = %d", code)
	}
}

func TestCLIJWEEncryptDecryptFlow(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "rsa.jwk")
	payloadPath := filepath.Join(dir, "payload.txt")
	jwePath := filepath.Join(dir, "msg.jwe")

	if err := os.WriteFile(payloadPath, []byte("top secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, code := runCLI(t, "jwk", "generate", "--type", "RSA", "--output", keyPath); code != 0 {
		t.Fatal("generate failed")
	}
	if _, code := runCLI(t, "jwe", "encrypt", "--key", keyPath, "--key-encryption", "RSA-OAEP",
		"--content-encryption", "A128GCM", "--output", jwePath, payloadPath); code != 0 {
		t.Fatal("encrypt failed")
	}
	out, code := runCLI(t, "jwe", "decrypt", "--key", keyPath, jwePath)
	if code != 0 {
		t.Fatalf("decrypt exit = %d", code)
	}
	if out != "top secret" {
		t.Errorf("decrypt payload = %q", out)
	}
}
