package cmd

import (
	"bytes"
	"math/rand"
	"os"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

// Property-based tests assert invariants that must hold for every key and every
// payload, across all supported algorithms, rather than for a single example.

type keySpec struct {
	keyType string
	curve   string
	size    int
	sigAlg  string // empty if the key cannot sign
}

func signableKeySpecs() []keySpec {
	return []keySpec{
		{keyType: "RSA", size: 2048, sigAlg: "RS256"},
		{keyType: "EC", curve: "P-256", size: 2048, sigAlg: "ES256"},
		{keyType: "EC", curve: "P-384", size: 2048, sigAlg: "ES384"},
		{keyType: "OKP", curve: "Ed25519", size: 2048, sigAlg: "EdDSA"},
		{keyType: "oct", size: 256, sigAlg: "HS256"},
	}
}

// randomPayload returns a deterministic pseudo-random payload for iteration i.
func randomPayload(r *rand.Rand) []byte {
	n := r.Intn(512) + 1
	buf := make([]byte, n)
	r.Read(buf)
	return buf
}

func TestPropertyGeneratedKeysAlwaysParse(t *testing.T) {
	t.Parallel()

	for _, spec := range signableKeySpecs() {
		spec := spec
		for _, format := range []string{"json", "pem"} {
			format := format
			// oct keys have no PEM representation in jwx.
			if spec.keyType == "oct" && format == "pem" {
				continue
			}
			t.Run(spec.keyType+"-"+spec.curve+"-"+format, func(t *testing.T) {
				t.Parallel()
				path := genKey(t, spec.keyType, spec.curve, spec.size, format, false)
				set, err := getKeyFile(path, format)
				if err != nil {
					t.Fatalf("generated key did not parse: %v", err)
				}
				if set.Len() != 1 {
					t.Fatalf("expected exactly one key, got %d", set.Len())
				}
			})
		}
	}
}

func TestPropertyPublicKeyDropsPrivateMaterial(t *testing.T) {
	t.Parallel()

	for _, spec := range signableKeySpecs() {
		spec := spec
		if spec.keyType == "oct" {
			continue // symmetric keys have no public form
		}
		t.Run(spec.keyType+"-"+spec.curve, func(t *testing.T) {
			t.Parallel()
			priv := genKey(t, spec.keyType, spec.curve, spec.size, "json", false)
			pubPath := genKeyPublicOf(t, priv)
			data, err := os.ReadFile(pubPath)
			if err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{`"d"`, `"p"`, `"q"`, `"dp"`, `"dq"`} {
				if strings.Contains(string(data), field) {
					t.Errorf("%s public key leaked %s", spec.keyType, field)
				}
			}
		})
	}
}

func TestPropertySignVerifyRoundTrip(t *testing.T) {
	t.Parallel()

	for _, spec := range signableKeySpecs() {
		spec := spec
		t.Run(spec.sigAlg, func(t *testing.T) {
			t.Parallel()
			r := rand.New(rand.NewSource(int64(len(spec.sigAlg)) + 1))
			keyPath := genKey(t, spec.keyType, spec.curve, spec.size, "json", false)
			keyset, err := getKeyFile(keyPath, "json")
			if err != nil {
				t.Fatal(err)
			}

			for i := 0; i < 25; i++ {
				payload := randomPayload(r)
				payloadPath := writeFile(t, "payload.bin", string(payload))
				jwsMessage := signWith(t, keyPath, spec.sigAlg, payloadPath, "")

				v := &jwsVerifier{Algorithm: spec.sigAlg}
				var buf bytes.Buffer
				if err := v.writeVerifyResult(&buf, []byte(jwsMessage), keyset); err != nil {
					t.Fatalf("verify failed on iteration %d: %v", i, err)
				}
				if !bytes.Equal(buf.Bytes(), payload) {
					t.Fatalf("payload mismatch on iteration %d", i)
				}
			}
		})
	}
}

func TestPropertyEncryptDecryptRoundTrip(t *testing.T) {
	t.Parallel()

	type encSpec struct {
		keyType    string
		curve      string
		keyEnc     string
		contentEnc string
	}
	specs := []encSpec{
		{keyType: "RSA", keyEnc: "RSA-OAEP", contentEnc: "A256GCM"},
		{keyType: "EC", curve: "P-256", keyEnc: "ECDH-ES", contentEnc: "A256CBC-HS512"},
	}

	for _, spec := range specs {
		spec := spec
		t.Run(spec.keyType+"-"+spec.keyEnc, func(t *testing.T) {
			t.Parallel()
			r := rand.New(rand.NewSource(int64(len(spec.keyEnc)) + 7))
			keyPath := genKey(t, spec.keyType, spec.curve, 2048, "json", false)

			for i := 0; i < 15; i++ {
				payload := randomPayload(r)
				payloadPath := writeFile(t, "payload.bin", string(payload))
				jweMessage := encryptWith(t, keyPath, spec.keyEnc, spec.contentEnc, payloadPath, i%2 == 0)
				got, err := decryptWith(t, keyPath, jweMessage)
				if err != nil {
					t.Fatalf("decrypt failed on iteration %d: %v", i, err)
				}
				if got != string(payload) {
					t.Fatalf("round-trip mismatch on iteration %d", i)
				}
			}
		})
	}
}

// keep jwk import in use for potential future assertions.
var _ = jwk.NewSet
