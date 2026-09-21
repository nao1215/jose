package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
)

// genKeyWith generates a key like genKey, with kid, alg, use, and --set.
func genKeyWith(t *testing.T, g *jwkGenerater) string {
	t.Helper()
	g.Output = filepath.Join(t.TempDir(), "key.json")
	if g.OutputFormat == "" {
		g.OutputFormat = "json"
	}
	if g.KeySize == 0 {
		g.KeySize = defaultKeySize
	}
	g.KeySet = jwk.NewSet()
	if err := g.valid(); err != nil {
		t.Fatalf("valid(): %v", err)
	}
	if err := g.generate(); err != nil {
		t.Fatalf("generate(): %v", err)
	}
	return g.Output
}

func TestJWKGenerateRecordsKeyParameters(t *testing.T) {
	t.Parallel()

	for _, public := range []bool{false, true} {
		t.Run(fmt.Sprintf("public=%v", public), func(t *testing.T) {
			t.Parallel()
			path := genKeyWith(t, &jwkGenerater{
				KeyType: "EC", Curve: "P-256", PublicKey: public,
				KeyID: "k1", Algorithm: "ES256", Use: "sig",
			})
			set := readKeySet(t, path, "json")
			key, _ := set.Key(0)
			if kid, _ := key.KeyID(); kid != "k1" {
				t.Errorf("kid = %q, want k1", kid)
			}
			if alg, _ := key.Algorithm(); alg.String() != "ES256" {
				t.Errorf("alg = %q, want ES256", alg)
			}
			if use, _ := key.KeyUsage(); use != "sig" {
				t.Errorf("use = %q, want sig", use)
			}
		})
	}
}

func TestJWKGenerateSetWrapsOneKey(t *testing.T) {
	t.Parallel()

	withSet := genKeyWith(t, &jwkGenerater{KeyType: "EC", Curve: "P-256", AsSet: true})
	data, err := os.ReadFile(withSet)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"keys"`) {
		t.Errorf("--set output is not a JWK Set: %s", data)
	}

	bare := genKeyWith(t, &jwkGenerater{KeyType: "EC", Curve: "P-256"})
	data, err = os.ReadFile(bare)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"keys"`) {
		t.Errorf("output without --set is a JWK Set: %s", data)
	}
}

func TestJWKGenerateKeyParameterValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		gen     *jwkGenerater
		wantErr error
	}{
		{
			name:    "unknown use",
			gen:     &jwkGenerater{KeyType: "EC", Curve: "P-256", KeySize: 2048, OutputFormat: "json", Use: "auth"},
			wantErr: ErrInvalidKeyUse,
		},
		{
			name:    "unknown alg",
			gen:     &jwkGenerater{KeyType: "EC", Curve: "P-256", KeySize: 2048, OutputFormat: "json", Algorithm: "ES256K"},
			wantErr: ErrInvalidKeyAlgorithm,
		},
		{
			name:    "alg for another curve",
			gen:     &jwkGenerater{KeyType: "EC", Curve: "P-384", KeySize: 2048, OutputFormat: "json", Algorithm: "ES256"},
			wantErr: ErrKeyAlgorithmMismatch,
		},
		{
			name:    "signature alg with use enc",
			gen:     &jwkGenerater{KeyType: "EC", Curve: "P-256", KeySize: 2048, OutputFormat: "json", Algorithm: "ES256", Use: "enc"},
			wantErr: ErrKeyUseMismatch,
		},
		{
			name:    "HS512 with a 256-bit key",
			gen:     &jwkGenerater{KeyType: "oct", KeySize: 256, OutputFormat: "json", Algorithm: "HS512"},
			wantErr: ErrKeyAlgorithmMismatch,
		},
		{
			name:    "A256KW with a 512-bit key",
			gen:     &jwkGenerater{KeyType: "oct", KeySize: 512, OutputFormat: "json", Algorithm: "A256KW"},
			wantErr: ErrKeyAlgorithmMismatch,
		},
		{
			name:    "kid with pem output",
			gen:     &jwkGenerater{KeyType: "EC", Curve: "P-256", KeySize: 2048, OutputFormat: "pem", KeyID: "k1"},
			wantErr: ErrKeyParametersForPem,
		},
		{
			name:    "set with pem output",
			gen:     &jwkGenerater{KeyType: "EC", Curve: "P-256", KeySize: 2048, OutputFormat: "pem", AsSet: true},
			wantErr: ErrKeyParametersForPem,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := tt.gen.valid(); !errors.Is(err, tt.wantErr) {
				t.Errorf("valid() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestAlgorithmFitsKeyAgreesWithJWX is a differential test: for every key jose
// can generate and every algorithm jose supports, a pair algorithmFitsKey
// accepts must be one jwx can actually sign or encrypt with, so --alg never
// records a pair that fails later. The reverse does not hold on purpose: jwx
// signs ES384 with a P-256 key, which RFC 7518 forbids, so jose rejects it.
func TestAlgorithmFitsKeyAgreesWithJWX(t *testing.T) {
	t.Parallel()

	keys := []struct {
		keyType, curve string
		size           int
	}{
		{"RSA", "", 2048}, {"EC", "P-256", 0}, {"EC", "P-384", 0}, {"EC", "P-521", 0},
		{"OKP", "Ed25519", 0}, {"OKP", "X25519", 0},
		{"oct", "", 256}, {"oct", "", 384}, {"oct", "", 512},
	}
	algs := append(append([]string{}, supportedSignatureAlgorithms()...), supportedKeyEncryptionAlgorithms()...)

	for _, k := range keys {
		k := k
		t.Run(fmt.Sprintf("%s%s%d", k.keyType, k.curve, k.size), func(t *testing.T) {
			t.Parallel()
			path := genKeyWith(t, &jwkGenerater{KeyType: k.keyType, Curve: k.curve, KeySize: k.size})
			key, _ := readKeySet(t, path, "json").Key(0)

			accepted := 0
			for _, alg := range algs {
				if !algorithmFitsKey(alg, k.keyType, k.curve, k.size) {
					continue
				}
				accepted++
				if alg == "dir" {
					// dir needs a content key of the content encryption's
					// length; checked below with A256GCM for 256-bit keys.
					continue
				}
				if !worksWithJWX(t, key, alg) {
					t.Errorf("algorithmFitsKey accepts %s for %s %s %d, but jwx cannot use it", alg, k.keyType, k.curve, k.size)
				}
			}
			if accepted == 0 {
				t.Errorf("no algorithm fits %s %s %d", k.keyType, k.curve, k.size)
			}
			if k.keyType == "oct" && k.size == 256 && !worksWithJWX(t, key, "dir") {
				t.Error("dir with a 256-bit key and A256GCM fails")
			}
		})
	}
}

// worksWithJWX reports whether jwx can sign (or encrypt) with key under alg.
func worksWithJWX(t *testing.T, key jwk.Key, alg string) bool {
	t.Helper()
	if sig, ok := jwa.LookupSignatureAlgorithm(alg); ok && contains(supportedSignatureAlgorithms(), alg) {
		_, err := jws.Sign([]byte("x"), jws.WithKey(sig, key))
		return err == nil
	}
	keyAlg, ok := jwa.LookupKeyEncryptionAlgorithm(alg)
	if !ok {
		t.Fatalf("unknown algorithm %s", alg)
	}
	encKey := key
	if key.KeyType() != jwa.OctetSeq() {
		pub, err := jwk.PublicKeyOf(key)
		if err != nil {
			t.Fatal(err)
		}
		encKey = pub
	}
	_, err := jwe.Encrypt([]byte("x"), jwe.WithKey(keyAlg, encKey), jwe.WithContentEncryption(jwa.A256GCM()))
	return err == nil
}

func TestJWKPublic(t *testing.T) {
	t.Parallel()

	t.Run("keeps kid alg use and drops private material", func(t *testing.T) {
		t.Parallel()
		priv := genKeyWith(t, &jwkGenerater{KeyType: "EC", Curve: "P-256", KeyID: "k1", Algorithm: "ES256", Use: "sig"})
		set, err := publicKeysOf([]string{priv}, "json")
		if err != nil {
			t.Fatal(err)
		}
		key, _ := set.Key(0)
		if key.Has("d") {
			t.Error("public key still has the private d parameter")
		}
		if kid, _ := key.KeyID(); kid != "k1" {
			t.Errorf("kid = %q, want k1", kid)
		}
		if alg, _ := key.Algorithm(); alg.String() != "ES256" {
			t.Errorf("alg = %q, want ES256", alg)
		}
	})

	t.Run("merges several files in order", func(t *testing.T) {
		t.Parallel()
		a := genKeyWith(t, &jwkGenerater{KeyType: "EC", Curve: "P-256", KeyID: "a"})
		b := genKeyWith(t, &jwkGenerater{KeyType: "OKP", Curve: "Ed25519", KeyID: "b"})
		set, err := publicKeysOf([]string{a, b}, "json")
		if err != nil {
			t.Fatal(err)
		}
		if set.Len() != 2 {
			t.Fatalf("len = %d, want 2", set.Len())
		}
		for i, want := range []string{"a", "b"} {
			key, _ := set.Key(i)
			if kid, _ := key.KeyID(); kid != want {
				t.Errorf("key %d kid = %q, want %q", i, kid, want)
			}
		}
	})

	t.Run("rejects a duplicate kid", func(t *testing.T) {
		t.Parallel()
		a := genKeyWith(t, &jwkGenerater{KeyType: "EC", Curve: "P-256", KeyID: "same"})
		b := genKeyWith(t, &jwkGenerater{KeyType: "EC", Curve: "P-256", KeyID: "same"})
		if _, err := publicKeysOf([]string{a, b}, "json"); !errors.Is(err, ErrDuplicateKeyID) {
			t.Errorf("err = %v, want %v", err, ErrDuplicateKeyID)
		}
	})

	t.Run("rejects an oct key", func(t *testing.T) {
		t.Parallel()
		oct := genKeyWith(t, &jwkGenerater{KeyType: "oct", KeySize: 256})
		if _, err := publicKeysOf([]string{oct}, "json"); !errors.Is(err, ErrSymmetricKeyHasNoPublic) {
			t.Errorf("err = %v, want %v", err, ErrSymmetricKeyHasNoPublic)
		}
	})

	t.Run("reads PEM", func(t *testing.T) {
		t.Parallel()
		pem := genKey(t, "EC", "P-256", 2048, "pem", false)
		set, err := publicKeysOf([]string{pem}, "pem")
		if err != nil {
			t.Fatal(err)
		}
		key, _ := set.Key(0)
		if key.Has("d") {
			t.Error("public key from PEM still has d")
		}
	})

	t.Run("reports a missing file", func(t *testing.T) {
		t.Parallel()
		if _, err := publicKeysOf([]string{filepath.Join(t.TempDir(), "nope")}, "json"); !errors.Is(err, ErrOpenFile) {
			t.Errorf("err = %v, want %v", err, ErrOpenFile)
		}
	})
}

func TestLabelOnlyKey(t *testing.T) {
	t.Parallel()

	t.Run("labels a PEM key", func(t *testing.T) {
		t.Parallel()
		set, err := publicKeysOf([]string{genKey(t, "EC", "P-256", 2048, "pem", false)}, "pem")
		if err != nil {
			t.Fatal(err)
		}
		if err := labelOnlyKey(set, keyParameters{KeyID: "k1", Algorithm: "ES256", Use: "sig"}); err != nil {
			t.Fatal(err)
		}
		key, _ := set.Key(0)
		if kid, _ := key.KeyID(); kid != "k1" {
			t.Errorf("kid = %q, want k1", kid)
		}
	})

	t.Run("labels an OKP key", func(t *testing.T) {
		t.Parallel()
		set, err := publicKeysOf([]string{genKey(t, "OKP", "Ed25519", 2048, "json", false)}, "json")
		if err != nil {
			t.Fatal(err)
		}
		if err := labelOnlyKey(set, keyParameters{Algorithm: "EdDSA"}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("rejects an alg for another curve", func(t *testing.T) {
		t.Parallel()
		set, err := publicKeysOf([]string{genKey(t, "EC", "P-256", 2048, "json", false)}, "json")
		if err != nil {
			t.Fatal(err)
		}
		if err := labelOnlyKey(set, keyParameters{Algorithm: "ES384"}); !errors.Is(err, ErrKeyAlgorithmMismatch) {
			t.Errorf("err = %v, want %v", err, ErrKeyAlgorithmMismatch)
		}
	})

	t.Run("rejects an unknown use", func(t *testing.T) {
		t.Parallel()
		set, err := publicKeysOf([]string{genKey(t, "EC", "P-256", 2048, "json", false)}, "json")
		if err != nil {
			t.Fatal(err)
		}
		if err := labelOnlyKey(set, keyParameters{Use: "auth"}); !errors.Is(err, ErrInvalidKeyUse) {
			t.Errorf("err = %v, want %v", err, ErrInvalidKeyUse)
		}
	})

	// The key's own alg and use count: a label must agree with what the key
	// already says, not only with the other flags.
	t.Run("rejects an alg that contradicts the key's use", func(t *testing.T) {
		t.Parallel()
		enc := genKeyWith(t, &jwkGenerater{KeyType: "EC", Curve: "P-256", Use: "enc"})
		set, err := publicKeysOf([]string{enc}, "json")
		if err != nil {
			t.Fatal(err)
		}
		if err := labelOnlyKey(set, keyParameters{Algorithm: "ES256"}); !errors.Is(err, ErrKeyUseMismatch) {
			t.Errorf("err = %v, want %v", err, ErrKeyUseMismatch)
		}
	})

	t.Run("rejects a use that contradicts the key's alg", func(t *testing.T) {
		t.Parallel()
		sig := genKeyWith(t, &jwkGenerater{KeyType: "EC", Curve: "P-256", Algorithm: "ES256"})
		set, err := publicKeysOf([]string{sig}, "json")
		if err != nil {
			t.Fatal(err)
		}
		if err := labelOnlyKey(set, keyParameters{Use: "enc"}); !errors.Is(err, ErrKeyUseMismatch) {
			t.Errorf("err = %v, want %v", err, ErrKeyUseMismatch)
		}
	})

	t.Run("replaces an alg when the result is consistent", func(t *testing.T) {
		t.Parallel()
		sig := genKeyWith(t, &jwkGenerater{KeyType: "EC", Curve: "P-256", Algorithm: "ES256", Use: "sig"})
		set, err := publicKeysOf([]string{sig}, "json")
		if err != nil {
			t.Fatal(err)
		}
		if err := labelOnlyKey(set, keyParameters{Algorithm: "ECDH-ES", Use: "enc"}); err != nil {
			t.Fatal(err)
		}
		key, _ := set.Key(0)
		if use, _ := key.KeyUsage(); use != "enc" {
			t.Errorf("use = %q, want enc", use)
		}
	})

	t.Run("rejects more than one key", func(t *testing.T) {
		t.Parallel()
		a := genKey(t, "EC", "P-256", 2048, "json", false)
		b := genKey(t, "EC", "P-256", 2048, "json", false)
		set, err := publicKeysOf([]string{a, b}, "json")
		if err != nil {
			t.Fatal(err)
		}
		if err := labelOnlyKey(set, keyParameters{KeyID: "k1"}); !errors.Is(err, ErrKeyParametersNeedOneKey) {
			t.Errorf("err = %v, want %v", err, ErrKeyParametersNeedOneKey)
		}
	})
}

func TestCLIJWKPublicSet(t *testing.T) {
	priv := genKeyWith(t, &jwkGenerater{KeyType: "EC", Curve: "P-256", KeyID: "k1", Algorithm: "ES256"})
	out, code := runCLI(t, "jwk", "public", "--set", priv)
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	set, err := jwk.Parse([]byte(out))
	if err != nil {
		t.Fatalf("output is not a JWK set: %v\n%s", err, out)
	}
	if !strings.Contains(out, `"keys"`) || set.Len() != 1 {
		t.Errorf("want a one-key JWK Set, got %s", out)
	}
}
