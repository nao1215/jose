package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

// Metamorphic tests assert that different ways of doing the same thing give the
// same result: the input path (file vs stdin vs argument) must not change a
// parsed payload, a private and its derived public key must verify alike, and a
// repeatedly overwritten output file must always stay parseable.

// parsePayload runs jws parse for the given args and returns the captured
// stdout.
func parsePayload(t *testing.T, args []string, stdin string) string {
	t.Helper()

	if stdin != "" {
		oldStdin := os.Stdin
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.WriteString(stdin); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		os.Stdin = r
		defer func() { os.Stdin = oldStdin }()
	}

	out, code := runCLI(t, args...)
	if code != 0 {
		t.Fatalf("jws parse exit = %d (args=%v)", code, args)
	}
	return out
}

func TestMetamorphicParseInputPathsAgree(t *testing.T) {
	// A JWS parsed from a file, from stdin, and from an inline argument must
	// yield exactly the same payload.
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ec.jwk")
	payloadPath := filepath.Join(dir, "payload.txt")
	if err := os.WriteFile(payloadPath, []byte("metamorphic"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, code := runCLI(t, "jwk", "generate", "--type", "EC", "--curve", "P-256", "--output", keyPath); code != 0 {
		t.Fatal("generate failed")
	}
	jwsMessage := signWith(t, keyPath, "ES256", payloadPath, "")
	jwsPath := filepath.Join(dir, "msg.jws")
	if err := os.WriteFile(jwsPath, []byte(jwsMessage), 0600); err != nil {
		t.Fatal(err)
	}

	fromFile := parsePayload(t, []string{"jws", "parse", jwsPath}, "")
	fromArg := parsePayload(t, []string{"jws", "parse", jwsMessage}, "")
	fromStdin := parsePayload(t, []string{"jws", "parse", "-"}, jwsMessage)

	if fromFile != fromArg || fromFile != fromStdin {
		t.Errorf("input paths disagree: file=%q arg=%q stdin=%q", fromFile, fromArg, fromStdin)
	}
	if fromFile != "metamorphic" {
		t.Errorf("unexpected payload: %q", fromFile)
	}
}

func TestMetamorphicPrivateAndPublicVerifyAlike(t *testing.T) {
	t.Parallel()

	priv := genKey(t, "EC", "P-256", 2048, "json", false)
	pubPath := genKeyPublicOf(t, priv)
	payloadPath := writeFile(t, "payload.txt", "same result")
	jwsMessage := signWith(t, priv, "ES256", payloadPath, "")

	privset, err := getKeyFile(priv, "json")
	if err != nil {
		t.Fatal(err)
	}
	pubset, err := getKeyFile(pubPath, "json")
	if err != nil {
		t.Fatal(err)
	}

	var withPriv, withPub bytes.Buffer
	if err := (&jwsVerifier{Algorithm: "ES256"}).writeVerifyResult(&withPriv, []byte(jwsMessage), privset); err != nil {
		t.Fatalf("verify with private key failed: %v", err)
	}
	if err := (&jwsVerifier{Algorithm: "ES256"}).writeVerifyResult(&withPub, []byte(jwsMessage), pubset); err != nil {
		t.Fatalf("verify with public key failed: %v", err)
	}
	if withPriv.String() != withPub.String() {
		t.Errorf("private vs public verification disagree: %q vs %q", withPriv.String(), withPub.String())
	}
}

func TestMetamorphicReEncryptDecryptsToSamePlaintext(t *testing.T) {
	t.Parallel()

	keyPath := genKey(t, "RSA", "", 2048, "json", false)
	payloadPath := writeFile(t, "payload.txt", "stable plaintext")

	var ciphertexts []string
	for i := 0; i < 5; i++ {
		ciphertexts = append(ciphertexts, encryptWith(t, keyPath, "RSA-OAEP", "A128GCM", payloadPath, false))
	}
	// Ciphertexts differ (fresh CEK/IV) but all decrypt to the same plaintext.
	for i := 1; i < len(ciphertexts); i++ {
		if ciphertexts[i] == ciphertexts[0] {
			t.Errorf("ciphertext %d unexpectedly equal to ciphertext 0", i)
		}
	}
	for i, c := range ciphertexts {
		got, err := decryptWith(t, keyPath, c)
		if err != nil {
			t.Fatalf("decrypt %d failed: %v", i, err)
		}
		if got != "stable plaintext" {
			t.Errorf("decrypt %d mismatch: %q", i, got)
		}
	}
}

func TestMetamorphicRepeatedOverwriteStaysParseable(t *testing.T) {
	t.Parallel()

	// Writing many keys of varying length to the same path must always leave a
	// parseable file, regardless of how the previous content compares in size.
	dir := t.TempDir()
	path := filepath.Join(dir, "key.jwk")

	specs := []keySpec{
		{keyType: "RSA", size: 4096},
		{keyType: "EC", curve: "P-256", size: 2048},
		{keyType: "oct", size: 256},
		{keyType: "RSA", size: 2048},
		{keyType: "OKP", curve: "Ed25519", size: 2048},
	}
	for i, spec := range specs {
		g := &jwkGenerater{
			KeyType:      spec.keyType,
			Curve:        spec.curve,
			KeySize:      spec.size,
			OutputFormat: "json",
			Output:       path,
			KeySet:       jwk.NewSet(),
		}
		if err := g.generate(); err != nil {
			t.Fatalf("generate %d (%s) failed: %v", i, spec.keyType, err)
		}
		if _, err := getKeyFile(path, "json"); err != nil {
			t.Fatalf("file not parseable after write %d (%s): %v", i, spec.keyType, err)
		}
	}
}
