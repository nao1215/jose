package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// Property-based tests assert invariants that must hold for every key and every
// payload, across all supported algorithms, rather than for a single example.
// rapid draws the payloads and shrinks a failing one to a minimal input; the
// failure output names the seed, and `go test -rapid.seed=<seed>` replays it.

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
		t.Run(spec.sigAlg, func(t *testing.T) {
			t.Parallel()
			keyPath := genKey(t, spec.keyType, spec.curve, spec.size, "json", false)
			keyset, err := getKeyFile(keyPath, "json")
			if err != nil {
				t.Fatal(err)
			}

			rapid.Check(t, func(rt *rapid.T) {
				payload := rapid.SliceOfN(rapid.Byte(), 1, 512).Draw(rt, "payload")
				jwsMessage := signWith(t, keyPath, spec.sigAlg, writeFile(t, "payload.bin", string(payload)), "")

				v := &jwsVerifier{Algorithm: spec.sigAlg}
				var buf bytes.Buffer
				if err := v.writeVerifyResult(&buf, []byte(jwsMessage), keyset); err != nil {
					rt.Fatalf("verify failed: %v", err)
				}
				if !bytes.Equal(buf.Bytes(), payload) {
					rt.Fatalf("verified payload %q, signed %q", buf.Bytes(), payload)
				}
			})
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
		{keyType: "OKP", curve: "X25519", keyEnc: "ECDH-ES+A128KW", contentEnc: "A128GCM"},
	}

	for _, spec := range specs {
		t.Run(spec.keyType+"-"+spec.keyEnc, func(t *testing.T) {
			t.Parallel()
			keyPath := genKey(t, spec.keyType, spec.curve, 2048, "json", false)

			rapid.Check(t, func(rt *rapid.T) {
				payload := rapid.SliceOfN(rapid.Byte(), 1, 512).Draw(rt, "payload")
				compress := rapid.Bool().Draw(rt, "compress")
				jweMessage := encryptWith(t, keyPath, spec.keyEnc, spec.contentEnc, writeFile(t, "payload.bin", string(payload)), compress)
				got, err := decryptWith(t, keyPath, jweMessage)
				if err != nil {
					rt.Fatalf("decrypt failed: %v", err)
				}
				if got != string(payload) {
					rt.Fatalf("decrypted %q, encrypted %q", got, payload)
				}
			})
		})
	}
}

// base64URLString draws a string over the unpadded base64url alphabet.
func base64URLString() *rapid.Generator[string] {
	return rapid.StringMatching(`[A-Za-z0-9_-]*`)
}

func TestPropertyIsBase64URLAcceptsEveryEncoding(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		data := rapid.SliceOf(rapid.Byte()).Draw(rt, "data")
		enc := base64.RawURLEncoding.EncodeToString(data)
		if !isBase64URL(enc) {
			rt.Fatalf("isBase64URL(%q) = false for an unpadded base64url encoding", enc)
		}
	})
}

func TestPropertyIsBase64URLRejectsAnyOtherCharacter(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		prefix := base64URLString().Draw(rt, "prefix")
		suffix := base64URLString().Draw(rt, "suffix")
		bad := rapid.Rune().Filter(func(r rune) bool {
			return !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", r)
		}).Draw(rt, "bad")
		s := prefix + string(bad) + suffix
		if isBase64URL(s) {
			rt.Fatalf("isBase64URL(%q) = true with %q in it", s, bad)
		}
	})
}

// A token jose signs is recognized as an inline token, so `jose jws verify
// <token>` never mistakes it for a file name.
func TestPropertySignedTokensLookLikeCompactJWS(t *testing.T) {
	t.Parallel()

	keyPath := genKey(t, "oct", "", 256, "json", false)
	rapid.Check(t, func(rt *rapid.T) {
		payload := rapid.SliceOfN(rapid.Byte(), 1, 256).Draw(rt, "payload")
		header := ""
		if rapid.Bool().Draw(rt, "header") {
			header = `{"kid":"` + base64URLString().Draw(rt, "kid") + `"}`
		}
		token := signWith(t, keyPath, "HS256", writeFile(t, "payload.bin", string(payload)), header)
		if !looksLikeCompactJWS(token) {
			rt.Fatalf("looksLikeCompactJWS(%q) = false for a token jose signed", token)
		}
	})
}

// Three base64url segments are only a JWS when the first decodes to JSON;
// anything else must be read as a file name.
func TestPropertyLooksLikeCompactJWSNeedsAJSONHeader(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		header := rapid.SliceOfN(rapid.Byte(), 1, 64).Draw(rt, "header")
		payload := base64URLString().Filter(func(s string) bool { return s != "" }).Draw(rt, "payload")
		sig := base64URLString().Draw(rt, "signature")
		s := base64.RawURLEncoding.EncodeToString(header) + "." + payload + "." + sig
		if got, want := looksLikeCompactJWS(s), json.Valid(header); got != want {
			rt.Fatalf("looksLikeCompactJWS(%q) = %v, header %q is valid JSON: %v", s, got, header, want)
		}
	})
}

func TestPropertyLooksLikeCompactJWSNeedsThreeSegments(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		n := rapid.IntRange(1, 6).Filter(func(n int) bool { return n != 3 }).Draw(rt, "segments")
		parts := []string{base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))}
		for len(parts) < n {
			parts = append(parts, base64URLString().Filter(func(s string) bool { return s != "" }).Draw(rt, "part"))
		}
		s := strings.Join(parts, ".")
		if looksLikeCompactJWS(s) {
			rt.Fatalf("looksLikeCompactJWS(%q) = true with %d segments", s, n)
		}
	})
}
