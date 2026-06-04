package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

// encryptWith encrypts the payload file with the given key and algorithms and
// returns the JWE compact serialization.
func encryptWith(t *testing.T, keyPath, keyEnc, contentEnc, payloadPath string, compress bool) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "out.jwe")
	e := &jweEncrypter{
		Compress:          compress,
		ContentEncryption: contentEnc,
		Key:               keyPath,
		KeyEncryption:     keyEnc,
		KeyFormat:         "json",
		InputFilePath:     payloadPath,
		Output:            out,
	}
	if err := e.valid(); err != nil {
		t.Fatalf("encrypter valid: %v", err)
	}
	if err := e.encrypt(); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// decryptWith decrypts the JWE message with the given key and returns the
// plaintext.
func decryptWith(t *testing.T, keyPath, jweMessage string) (string, error) {
	t.Helper()
	in := writeFile(t, "msg.jwe", jweMessage)
	out := filepath.Join(t.TempDir(), "plain.txt")
	d := &jweDecrypter{
		Key:           keyPath,
		KeyFormat:     "json",
		InputFilePath: in,
		Output:        out,
	}
	if err := d.valid(); err != nil {
		return "", err
	}
	if err := d.decrypt(); err != nil {
		return "", err
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return string(data), nil
}

func TestJWEEncryptDecryptRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		keyType    string
		curve      string
		size       int
		keyEnc     string
		contentEnc string
		compress   bool
	}{
		{name: "EC ECDH-ES A256CBC", keyType: "EC", curve: "P-256", size: 2048, keyEnc: "ECDH-ES", contentEnc: "A256CBC-HS512"},
		{name: "EC ECDH-ES A128GCM", keyType: "EC", curve: "P-256", size: 2048, keyEnc: "ECDH-ES", contentEnc: "A128GCM"},
		{name: "RSA RSA-OAEP A128GCM", keyType: "RSA", size: 2048, keyEnc: "RSA-OAEP", contentEnc: "A128GCM"},
		{name: "RSA OAEP compressed", keyType: "RSA", size: 2048, keyEnc: "RSA-OAEP-256", contentEnc: "A256GCM", compress: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			keyPath := genKey(t, tt.keyType, tt.curve, tt.size, "json", false)
			payloadPath := writeFile(t, "payload.txt", "secret message")

			jweMessage := encryptWith(t, keyPath, tt.keyEnc, tt.contentEnc, payloadPath, tt.compress)
			got, err := decryptWith(t, keyPath, jweMessage)
			if err != nil {
				t.Fatalf("decrypt failed: %v", err)
			}
			if got != "secret message" {
				t.Errorf("round-trip mismatch: got %q", got)
			}
		})
	}
}

func TestJWEEncryptIsNonDeterministicButDecryptsSame(t *testing.T) {
	t.Parallel()

	keyPath := genKey(t, "RSA", "", 2048, "json", false)
	payloadPath := writeFile(t, "payload.txt", "same plaintext")

	a := encryptWith(t, keyPath, "RSA-OAEP", "A128GCM", payloadPath, false)
	b := encryptWith(t, keyPath, "RSA-OAEP", "A128GCM", payloadPath, false)
	if a == b {
		t.Error("two encryptions of the same plaintext produced identical ciphertext")
	}

	for _, c := range []string{a, b} {
		got, err := decryptWith(t, keyPath, c)
		if err != nil {
			t.Fatal(err)
		}
		if got != "same plaintext" {
			t.Errorf("decrypt mismatch: %q", got)
		}
	}
}

func TestJWEDecryptWithPemKey(t *testing.T) {
	t.Parallel()

	// Generate an RSA key in PEM, encrypt and decrypt using it.
	pemPath := genKey(t, "RSA", "", 2048, "pem", false)
	payloadPath := writeFile(t, "payload.txt", "pem secret")

	out := filepath.Join(t.TempDir(), "msg.jwe")
	enc := &jweEncrypter{
		ContentEncryption: "A128GCM",
		Key:               pemPath,
		KeyEncryption:     "RSA-OAEP",
		KeyFormat:         "pem",
		InputFilePath:     payloadPath,
		Output:            out,
	}
	if err := enc.valid(); err != nil {
		t.Fatal(err)
	}
	if err := enc.encrypt(); err != nil {
		t.Fatalf("encrypt with pem failed: %v", err)
	}

	plain := filepath.Join(t.TempDir(), "plain.txt")
	dec := &jweDecrypter{
		Key:           pemPath,
		KeyFormat:     "pem",
		InputFilePath: out,
		Output:        plain,
	}
	if err := dec.decrypt(); err != nil {
		t.Fatalf("decrypt with pem failed: %v", err)
	}
	data, err := os.ReadFile(plain)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "pem secret" {
		t.Errorf("pem round-trip mismatch: %q", string(data))
	}
}

func TestJWEEncryptValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		enc     *jweEncrypter
		wantErr error
	}{
		{
			name:    "missing key",
			enc:     &jweEncrypter{ContentEncryption: "A128GCM", KeyEncryption: "RSA-OAEP", KeyFormat: "json"},
			wantErr: ErrRequireKeyFile,
		},
		{
			name:    "invalid content encryption",
			enc:     &jweEncrypter{ContentEncryption: "BOGUS", Key: "k.json", KeyEncryption: "RSA-OAEP", KeyFormat: "json"},
			wantErr: ErrInvalidContentEncryption,
		},
		{
			name:    "invalid key encryption",
			enc:     &jweEncrypter{ContentEncryption: "A128GCM", Key: "k.json", KeyEncryption: "BOGUS", KeyFormat: "json"},
			wantErr: ErrInvalidKeyEncryption,
		},
		{
			name:    "invalid key format",
			enc:     &jweEncrypter{ContentEncryption: "A128GCM", Key: "k.json", KeyEncryption: "RSA-OAEP", KeyFormat: "der"},
			wantErr: ErrInvalidKeyFormat,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := tt.enc.valid(); !errors.Is(err, tt.wantErr) {
				t.Errorf("valid() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestJWEDecryptValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		dec     *jweDecrypter
		wantErr error
	}{
		{
			name:    "missing key",
			dec:     &jweDecrypter{KeyFormat: "json"},
			wantErr: ErrRequireKeyFile,
		},
		{
			name:    "invalid key encryption",
			dec:     &jweDecrypter{Key: "k.json", KeyEncryption: "BOGUS", KeyFormat: "json"},
			wantErr: ErrInvalidKeyEncryption,
		},
		{
			name:    "invalid key format",
			dec:     &jweDecrypter{Key: "k.json", KeyFormat: "der"},
			wantErr: ErrInvalidKeyFormat,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := tt.dec.valid(); !errors.Is(err, tt.wantErr) {
				t.Errorf("valid() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestJWEDecryptWithExplicitKeyEncryption(t *testing.T) {
	t.Parallel()

	keyPath := genKey(t, "RSA", "", 2048, "json", false)
	payloadPath := writeFile(t, "payload.txt", "explicit alg")
	jweMessage := encryptWith(t, keyPath, "RSA-OAEP", "A128GCM", payloadPath, false)

	in := writeFile(t, "msg.jwe", jweMessage)
	out := filepath.Join(t.TempDir(), "plain.txt")
	d := &jweDecrypter{
		Key:           keyPath,
		KeyEncryption: "RSA-OAEP",
		KeyFormat:     "json",
		InputFilePath: in,
		Output:        out,
	}
	if err := d.valid(); err != nil {
		t.Fatal(err)
	}
	if err := d.decrypt(); err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "explicit alg" {
		t.Errorf("mismatch: %q", string(data))
	}
}

// ensure jwk import stays used even if helpers change.
var _ = jwk.NewSet

func TestJWEDecryptGarbageFails(t *testing.T) {
	t.Parallel()

	keyPath := genKey(t, "RSA", "", 2048, "json", false)
	if _, err := decryptWith(t, keyPath, "not-a-jwe-message"); err == nil {
		t.Error("expected error decrypting garbage, got nil")
	}
}

func TestJWEEncryptDecryptViaBuffer(t *testing.T) {
	t.Parallel()

	keyPath := genKey(t, "EC", "P-256", 2048, "json", false)
	payloadPath := writeFile(t, "payload.txt", "buffered")
	jweMessage := encryptWith(t, keyPath, "ECDH-ES", "A256GCM", payloadPath, false)

	keyset, err := getKeyFile(keyPath, "json")
	if err != nil {
		t.Fatal(err)
	}
	key, _ := keyset.Key(0)
	d := &jweDecrypter{}
	plain, err := d.decryptMessage([]byte(jweMessage), key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, []byte("buffered")) {
		t.Errorf("mismatch: %q", string(plain))
	}
}
