package cmd

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func TestNewJwkGenerater(t *testing.T) {
	t.Parallel()
	t.Run("Get all options", func(t *testing.T) {
		t.Parallel()

		cmd := newJWKGenerateCmd()
		if err := cmd.Flags().Set("curve", "Ed25519"); err != nil {
			t.Fatal(err)
		}
		if err := cmd.Flags().Set("type", "RSA"); err != nil {
			t.Fatal(err)
		}
		if err := cmd.Flags().Set("size", "4096"); err != nil {
			t.Fatal(err)
		}
		if err := cmd.Flags().Set("output-format", "pem"); err != nil {
			t.Fatal(err)
		}
		if err := cmd.Flags().Set("output", "test.pem"); err != nil {
			t.Fatal(err)
		}
		if err := cmd.Flags().Set("public-key", "true"); err != nil {
			t.Fatal(err)
		}

		got, err := newJWKGenerater(cmd)
		if err != nil {
			t.Fatal(err)
		}

		want := &jwkGenerater{
			Curve:        "Ed25519",
			KeyType:      "RSA",
			KeySize:      4096,
			OutputFormat: "pem",
			Output:       "test.pem",
			PublicKey:    true,
			KeySet:       jwk.NewSet(),
		}

		opt := cmpopts.IgnoreFields(jwkGenerater{}, "KeySet")
		if diff := cmp.Diff(want, got, opt); diff != "" {
			t.Errorf("value is mismatch (-want +got):\n%s", diff)
		}
	})
}

// readKeySet reads a JWK (or JWK set) file and fails the test if it cannot be
// parsed. This is the core round-trip guarantee: anything jose writes must be
// readable again.
func readKeySet(t *testing.T, path, format string) jwk.Set {
	t.Helper()
	set, err := getKeyFile(path, format)
	if err != nil {
		t.Fatalf("getKeyFile(%s): %v", path, err)
	}
	return set
}

func TestJWKGenerateAllKeyTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		keyType string
		curve   string
		size    int
		format  string
		wantKty string
	}{
		{name: "RSA json", keyType: "RSA", size: 2048, format: "json", wantKty: "RSA"},
		{name: "RSA pem", keyType: "RSA", size: 2048, format: "pem", wantKty: "RSA"},
		{name: "EC P-256 json", keyType: "EC", curve: "P-256", size: 2048, format: "json", wantKty: "EC"},
		{name: "EC P-384 json", keyType: "EC", curve: "P-384", size: 2048, format: "json", wantKty: "EC"},
		{name: "EC P-521 pem", keyType: "EC", curve: "P-521", size: 2048, format: "pem", wantKty: "EC"},
		{name: "OKP Ed25519 json", keyType: "OKP", curve: "Ed25519", size: 2048, format: "json", wantKty: "OKP"},
		{name: "OKP X25519 json", keyType: "OKP", curve: "X25519", size: 2048, format: "json", wantKty: "OKP"},
		{name: "oct json", keyType: "oct", size: 256, format: "json", wantKty: "oct"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			path := genKey(t, tt.keyType, tt.curve, tt.size, tt.format, false)
			set := readKeySet(t, path, tt.format)
			if set.Len() != 1 {
				t.Fatalf("expected 1 key, got %d", set.Len())
			}
			key, _ := set.Key(0)
			if got := key.KeyType().String(); got != tt.wantKty {
				t.Errorf("kty mismatch: want=%s got=%s", tt.wantKty, got)
			}
		})
	}
}

func TestJWKGeneratePublicKeyHasNoPrivateMaterial(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		keyType string
		curve   string
	}{
		{name: "RSA", keyType: "RSA", curve: ""},
		{name: "EC", keyType: "EC", curve: "P-256"},
		{name: "OKP Ed25519", keyType: "OKP", curve: "Ed25519"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			path := genKey(t, tt.keyType, tt.curve, 2048, "json", true)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			// The RFC 7517 private fields must be absent from a public key.
			for _, field := range []string{`"d"`, `"p"`, `"q"`} {
				if strings.Contains(string(data), field) {
					t.Errorf("public key unexpectedly contains private field %s:\n%s", field, data)
				}
			}
		})
	}
}

func TestJWKGenerateOctetSize(t *testing.T) {
	t.Parallel()

	// --size is in bits, so 256 bits must yield 32 raw bytes.
	path := genKey(t, "oct", "", 256, "json", false)
	set := readKeySet(t, path, "json")
	key, _ := set.Key(0)

	var raw []byte
	if err := key.Raw(&raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 32 {
		t.Errorf("oct key size mismatch: want=32 bytes (256 bits), got=%d bytes", len(raw))
	}
}

func TestJWKGenerateOverwriteLeavesParseableFile(t *testing.T) {
	t.Parallel()

	// Regression for the truncation bug: writing a long RSA key and then a
	// short EC key to the same path must leave a parseable file, not RSA
	// garbage trailing the EC JSON.
	dir := t.TempDir()
	path := dir + "/overwrite.jwk"

	rsa := &jwkGenerater{KeyType: "RSA", KeySize: 4096, OutputFormat: "json", Output: path, KeySet: jwk.NewSet()}
	if err := rsa.generate(); err != nil {
		t.Fatal(err)
	}

	ec := &jwkGenerater{KeyType: "EC", Curve: "P-256", KeySize: 2048, OutputFormat: "json", Output: path, KeySet: jwk.NewSet()}
	if err := ec.generate(); err != nil {
		t.Fatal(err)
	}

	set := readKeySet(t, path, "json")
	key, _ := set.Key(0)
	if got := key.KeyType().String(); got != "EC" {
		t.Errorf("after overwrite want EC, got %s", got)
	}
}

func TestJWKGenerateValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		gen     *jwkGenerater
		wantErr error
	}{
		{
			name:    "unsupported key type",
			gen:     &jwkGenerater{KeyType: "DSA", KeySize: 2048, OutputFormat: "json"},
			wantErr: ErrKeyType,
		},
		{
			name:    "EC without curve",
			gen:     &jwkGenerater{KeyType: "EC", KeySize: 2048, OutputFormat: "json"},
			wantErr: ErrRequireCurve,
		},
		{
			name:    "EC with OKP curve",
			gen:     &jwkGenerater{KeyType: "EC", Curve: "Ed25519", KeySize: 2048, OutputFormat: "json"},
			wantErr: ErrInvalidCurve,
		},
		{
			name:    "OKP with unsupported X448 curve",
			gen:     &jwkGenerater{KeyType: "OKP", Curve: "X448", KeySize: 2048, OutputFormat: "json"},
			wantErr: ErrInvalidCurve,
		},
		{
			name:    "OKP with unsupported Ed448 curve",
			gen:     &jwkGenerater{KeyType: "OKP", Curve: "Ed448", KeySize: 2048, OutputFormat: "json"},
			wantErr: ErrInvalidCurve,
		},
		{
			name:    "RSA size not multiple of 8",
			gen:     &jwkGenerater{KeyType: "RSA", KeySize: 2050, OutputFormat: "json"},
			wantErr: ErrKeySize,
		},
		{
			name:    "RSA size too small",
			gen:     &jwkGenerater{KeyType: "RSA", KeySize: 128, OutputFormat: "json"},
			wantErr: ErrKeySize,
		},
		{
			name:    "invalid output format",
			gen:     &jwkGenerater{KeyType: "RSA", KeySize: 2048, OutputFormat: "xml"},
			wantErr: ErrInvalidKeyFormat,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.gen.valid()
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("valid() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestJWKGenerateUnsupportedOKPCurveErrorsAtGenerate(t *testing.T) {
	t.Parallel()

	// Even if validation were bypassed, generating an OKP key for a curve jose
	// cannot produce must fail with a clear error, not a nil-key panic.
	g := &jwkGenerater{KeyType: "OKP", Curve: "X448", KeySize: 2048, OutputFormat: "json", Output: "-", KeySet: jwk.NewSet()}
	if _, err := g.generateOKP(); err == nil {
		t.Error("expected error generating OKP X448, got nil")
	}
}
