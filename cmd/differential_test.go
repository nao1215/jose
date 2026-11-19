package cmd

import (
	"bytes"
	"crypto"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	gojose "github.com/go-jose/go-jose/v4"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"pgregory.net/rapid"
)

// Differential tests check jose against go-jose, a second JOSE implementation
// that shares no code with jwx. A message jose signs or encrypts must verify
// or decrypt with go-jose, and the other way round, for any payload. Both
// sides read the key from the JWK file jose wrote, so the key encoding is
// compared too. A disagreement means one side does not follow RFC 7515 /
// 7516 / 7517 for that algorithm.

// readGoJoseKey parses the JWK file jose wrote with go-jose's own decoder.
func readGoJoseKey(t *testing.T, path string) gojose.JSONWebKey {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // the path comes from t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	var key gojose.JSONWebKey
	if err := json.Unmarshal(data, &key); err != nil {
		t.Fatalf("go-jose cannot read the JWK jose wrote: %v\n%s", err, data)
	}
	// go-jose's Valid only knows asymmetric key types and reports every
	// symmetric ([]byte) key as invalid, so it is asked about those only.
	if _, symmetric := key.Key.([]byte); !symmetric && !key.Valid() {
		t.Fatalf("go-jose reports the JWK jose wrote as invalid:\n%s", data)
	}
	return key
}

// publicOf returns the key go-jose verifies or encrypts with: the public half
// of an asymmetric key and the key itself for a symmetric one.
func publicOf(key gojose.JSONWebKey) any {
	if key.IsPublic() {
		return key.Key
	}
	if pub := key.Public(); pub.Key != nil {
		return pub.Key
	}
	return key.Key
}

type diffSignSpec struct {
	keyType string
	curve   string
	size    int
	alg     string
}

func diffSignSpecs() []diffSignSpec {
	return []diffSignSpec{
		{keyType: "RSA", size: 2048, alg: "RS256"},
		{keyType: "RSA", size: 2048, alg: "RS512"},
		{keyType: "RSA", size: 2048, alg: "PS256"},
		{keyType: "RSA", size: 2048, alg: "PS384"},
		{keyType: "EC", curve: "P-256", alg: "ES256"},
		{keyType: "EC", curve: "P-384", alg: "ES384"},
		{keyType: "EC", curve: "P-521", alg: "ES512"},
		{keyType: "OKP", curve: "Ed25519", alg: "EdDSA"},
		{keyType: "oct", size: 256, alg: "HS256"},
		{keyType: "oct", size: 512, alg: "HS512"},
	}
}

func TestDifferentialGoJoseVerifiesWhatJoseSigns(t *testing.T) {
	t.Parallel()

	for _, spec := range diffSignSpecs() {
		t.Run(spec.alg, func(t *testing.T) {
			t.Parallel()
			keyPath := genKey(t, spec.keyType, spec.curve, spec.size, "json", false)
			key := readGoJoseKey(t, keyPath)
			alg := gojose.SignatureAlgorithm(spec.alg)

			rapid.Check(t, func(rt *rapid.T) {
				payload := rapid.SliceOfN(rapid.Byte(), 1, 512).Draw(rt, "payload")
				token := signWith(t, keyPath, spec.alg, writeFile(t, "payload.bin", string(payload)), "")

				parsed, err := gojose.ParseSignedCompact(token, []gojose.SignatureAlgorithm{alg})
				if err != nil {
					rt.Fatalf("go-jose cannot parse the JWS jose signed: %v", err)
				}
				got, err := parsed.Verify(publicOf(key))
				if err != nil {
					rt.Fatalf("go-jose rejects the signature jose made: %v", err)
				}
				if !bytes.Equal(got, payload) {
					rt.Fatalf("go-jose verified payload %q, jose signed %q", got, payload)
				}
			})
		})
	}
}

func TestDifferentialJoseVerifiesWhatGoJoseSigns(t *testing.T) {
	t.Parallel()

	for _, spec := range diffSignSpecs() {
		t.Run(spec.alg, func(t *testing.T) {
			t.Parallel()
			keyPath := genKey(t, spec.keyType, spec.curve, spec.size, "json", false)
			key := readGoJoseKey(t, keyPath)
			keyset, err := getKeyFile(keyPath, "json")
			if err != nil {
				t.Fatal(err)
			}
			signer, err := gojose.NewSigner(gojose.SigningKey{Algorithm: gojose.SignatureAlgorithm(spec.alg), Key: key.Key}, nil)
			if err != nil {
				t.Fatal(err)
			}

			rapid.Check(t, func(rt *rapid.T) {
				payload := rapid.SliceOfN(rapid.Byte(), 1, 512).Draw(rt, "payload")
				signed, err := signer.Sign(payload)
				if err != nil {
					rt.Fatal(err)
				}
				token, err := signed.CompactSerialize()
				if err != nil {
					rt.Fatal(err)
				}

				v := &jwsVerifier{Algorithm: spec.alg}
				var out bytes.Buffer
				if err := v.writeVerifyResult(&out, []byte(token), keyset); err != nil {
					rt.Fatalf("jose rejects the signature go-jose made: %v", err)
				}
				if !bytes.Equal(out.Bytes(), payload) {
					rt.Fatalf("jose verified payload %q, go-jose signed %q", out.Bytes(), payload)
				}
			})
		})
	}
}

type diffEncSpec struct {
	keyType    string
	curve      string
	keyEnc     string
	contentEnc string
}

func diffEncSpecs() []diffEncSpec {
	return []diffEncSpec{
		{keyType: "RSA", keyEnc: "RSA-OAEP", contentEnc: "A128GCM"},
		{keyType: "RSA", keyEnc: "RSA-OAEP-256", contentEnc: "A256GCM"},
		{keyType: "RSA", keyEnc: "RSA-OAEP-256", contentEnc: "A128CBC-HS256"},
		{keyType: "EC", curve: "P-256", keyEnc: "ECDH-ES", contentEnc: "A256GCM"},
		{keyType: "EC", curve: "P-384", keyEnc: "ECDH-ES+A128KW", contentEnc: "A192GCM"},
		{keyType: "EC", curve: "P-521", keyEnc: "ECDH-ES+A256KW", contentEnc: "A256CBC-HS512"},
	}
}

func TestDifferentialGoJoseDecryptsWhatJoseEncrypts(t *testing.T) {
	t.Parallel()

	for _, spec := range diffEncSpecs() {
		t.Run(spec.keyEnc+"-"+spec.contentEnc, func(t *testing.T) {
			t.Parallel()
			keyPath := genKey(t, spec.keyType, spec.curve, 2048, "json", false)
			key := readGoJoseKey(t, keyPath)

			rapid.Check(t, func(rt *rapid.T) {
				payload := rapid.SliceOfN(rapid.Byte(), 1, 512).Draw(rt, "payload")
				compress := rapid.Bool().Draw(rt, "compress")
				token := encryptWith(t, keyPath, spec.keyEnc, spec.contentEnc, writeFile(t, "payload.bin", string(payload)), compress)

				parsed, err := gojose.ParseEncryptedCompact(token,
					[]gojose.KeyAlgorithm{gojose.KeyAlgorithm(spec.keyEnc)},
					[]gojose.ContentEncryption{gojose.ContentEncryption(spec.contentEnc)})
				if err != nil {
					rt.Fatalf("go-jose cannot parse the JWE jose encrypted: %v", err)
				}
				got, err := parsed.Decrypt(key.Key)
				if err != nil {
					rt.Fatalf("go-jose cannot decrypt the JWE jose encrypted: %v", err)
				}
				if !bytes.Equal(got, payload) {
					rt.Fatalf("go-jose decrypted %q, jose encrypted %q", got, payload)
				}
			})
		})
	}
}

func TestDifferentialJoseDecryptsWhatGoJoseEncrypts(t *testing.T) {
	t.Parallel()

	for _, spec := range diffEncSpecs() {
		t.Run(spec.keyEnc+"-"+spec.contentEnc, func(t *testing.T) {
			t.Parallel()
			keyPath := genKey(t, spec.keyType, spec.curve, 2048, "json", false)
			key := readGoJoseKey(t, keyPath)
			keyset, err := getKeyFile(keyPath, "json")
			if err != nil {
				t.Fatal(err)
			}
			jwxKey, _ := keyset.Key(0)

			rapid.Check(t, func(rt *rapid.T) {
				payload := rapid.SliceOfN(rapid.Byte(), 1, 512).Draw(rt, "payload")
				opts := &gojose.EncrypterOptions{}
				if rapid.Bool().Draw(rt, "compress") {
					opts.Compression = gojose.DEFLATE
				}
				enc, err := gojose.NewEncrypter(gojose.ContentEncryption(spec.contentEnc),
					gojose.Recipient{Algorithm: gojose.KeyAlgorithm(spec.keyEnc), Key: publicOf(key)}, opts)
				if err != nil {
					rt.Fatal(err)
				}
				obj, err := enc.Encrypt(payload)
				if err != nil {
					rt.Fatal(err)
				}
				token, err := obj.CompactSerialize()
				if err != nil {
					rt.Fatal(err)
				}

				// Without --key-encryption jose takes the algorithm from the
				// header; with it, it insists on that one. Both must agree.
				for _, keyEnc := range []string{"", spec.keyEnc} {
					d := &jweDecrypter{KeyEncryption: keyEnc}
					got, err := d.decryptMessage([]byte(token), jwxKey)
					if err != nil {
						rt.Fatalf("jose (--key-encryption %q) cannot decrypt the JWE go-jose encrypted: %v", keyEnc, err)
					}
					if !bytes.Equal(got, payload) {
						rt.Fatalf("jose decrypted %q, go-jose encrypted %q", got, payload)
					}
				}
			})
		})
	}
}

// TestDifferentialPublicJWKMatchesGoJose checks that the public key jose
// derives from a private JWK is the one go-jose derives from the same file.
func TestDifferentialPublicJWKMatchesGoJose(t *testing.T) {
	t.Parallel()

	for _, spec := range diffSignSpecs() {
		if spec.keyType == "oct" {
			continue // a symmetric key has no public half
		}
		t.Run(spec.keyType+"-"+spec.curve+"-"+spec.alg, func(t *testing.T) {
			t.Parallel()
			priv := genKey(t, spec.keyType, spec.curve, spec.size, "json", false)
			set, err := publicKeysOf([]string{priv}, "json")
			if err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			if err := writeKeys(&buf, set, false); err != nil {
				t.Fatal(err)
			}
			pubPath := filepath.Join(t.TempDir(), "pub.json")
			if err := os.WriteFile(pubPath, buf.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}

			fromJose := readGoJoseKey(t, pubPath)
			if !fromJose.IsPublic() {
				t.Fatalf("jose jwk public wrote a key go-jose reads as private:\n%s", buf.Bytes())
			}
			privKey := readGoJoseKey(t, priv)
			fromGoJose := privKey.Public()
			a, err := fromJose.Thumbprint(crypto.SHA256)
			if err != nil {
				t.Fatal(err)
			}
			b, err := fromGoJose.Thumbprint(crypto.SHA256)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(a, b) {
				t.Fatalf("public key thumbprints differ: jose %x, go-jose %x", a, b)
			}
		})
	}
}

// The algorithm names jose lists must be names go-jose knows too, so a user
// copying one from `jose jwa` gets the RFC 7518 spelling.
func TestDifferentialAlgorithmNamesAreKnownToGoJose(t *testing.T) {
	t.Parallel()

	known := map[string]bool{}
	for _, a := range []gojose.SignatureAlgorithm{
		gojose.EdDSA, gojose.HS256, gojose.HS384, gojose.HS512, gojose.RS256, gojose.RS384, gojose.RS512,
		gojose.ES256, gojose.ES384, gojose.ES512, gojose.PS256, gojose.PS384, gojose.PS512,
	} {
		known[string(a)] = true
	}
	for _, spec := range diffSignSpecs() {
		if _, ok := jwa.LookupSignatureAlgorithm(spec.alg); !ok {
			t.Errorf("jwx does not know %s", spec.alg)
		}
		if !known[spec.alg] {
			t.Errorf("go-jose does not know %s", spec.alg)
		}
	}
}
