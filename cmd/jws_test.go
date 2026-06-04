package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

// issueRSAPrivateJWK is the RSA private key reported in issue #54.
// https://github.com/nao1215/jose/issues/54
const issueRSAPrivateJWK = `{
    "d": "C22ITIdhTzA44fW0CYBcMHCFzInJ5-Y6MJMfloPFmhxDnO2O_s4HZNZAGH1IJh3hHc1qlZW14P6OcfIXWxq_5Prr65SeeAq59GHXk_QovCCvjIaNWFlFlXtqsPBuQtOlkJXrfkPC95hEqS2wBMGizPr46sDHXNvrZyDyBBhSbUs6EpYgIQZrAGSDzXmDUlyU-wQDSnshHWGr9dQjObNKo_o03aWbPt27d2OivRhXV6zSChCkHIiSJfszM0lgv_BBXiDos23oSb5uP5SIimRheuFIZmqHzv-GvuQZu1PFSKpNNFM0s5TBLhtazO17Lkr6Lxb9g7JnfubT3SEBEUMvYQ",
    "dp": "FgxOPI9e58cZrrY2hPjaJCBwjWMDrZWveU-TgSdiDUTkR7sXIc4qo9K5njMEfUas1T46mVYX6DvJyHFqRAVJg-NIJMVvyhQ_9qOgP66B9UotPjKQAygWdudpeyx1_VxxP5Zc5P754uUpVzZJgKjjRM4PMQLrun-Oo0SLJu7XKPs",
    "dq": "kPBjNtYi573k-gtIgrxRBuxCQmGIZtpxvtjosEgdvs4tDy9fTF4OPVBPeVbKecYq8JE8_dZYTApxQU5C897lbHHwJMAjegpYus7x0ywSaaQsFLTZupbPOj34A3cZd49sEQtbehmmz4--9cfPyNSPHwcJvMhNlYv1GnQFqFvIWtE",
    "e": "AQAB",
    "kty": "RSA",
    "n": "t-0fT_LJl3u6uwHix3GFVMqTrn8l07_BDmqijgrSGUPBNOIR4KFVLZ69B2Eb4DC81inE10ei35ZYjNveoRNM7xOr6ed8BJoG_DcR969R_5Yb_V2qbg71XBoqBLkIwUBm3gTIb5t88R1wP4TabsCZ0JU-OPCKqjPR66cM4_tha_4iu90U9m4pwkP7kJYmlyaviHtAx3iOZLIZ0KXKGvqCQ4FqBrdaz-2b6kE5D8iByb9sAOIjq85eipQXluOtsSZBnPHEnG3y-OJ7yuzJIxqEi5r6yzZST0P-XufhWHmhrKePZQ5O1lCB0o0jubo9nfuYlq1BqXct1JYbLH_tDb3rHQ",
    "p": "0g3tzAidKcrWWYjiYkxB1QBcNisiXxjckkr7E95UDhousL8XqigiT8PEC1ZAio52Q-tNgIc1yZSsYxwyqlow8aCoNmRtGHOXKXqn0AVrgXmZrGiUxiKFahg0MmL1wmN13C9a5EUtgkDWOMaasxd61ZZib3_cLYYziS4f6SZfMEc",
    "q": "4Cgja6-K1kv0KLHd9ti7JoCDvL-kax1jRqxjOiUa3VLDVLMZWNyKxgti5D-f1AY28VVJT1QU5IRn4dbyJHOQI1MnbcHl9rUnnN_v96y20NJ1yJ7M6aB2zLSrGBxmKPCzmCMQ5l4_XfF-BxjTltyfaVi8s1BWZlKDl0b_D1Q9_3s",
    "qi": "xr_CNh_MSgSN4s2P-Ca6sIhsqoD-Y23jIlXHG95pXeSZyyotkdRJsqUZ0Pd292OOIgpFmB64UC_LlFMUmxhbojEdgTux2-K8yiwMJmdLfimdstBXRd_ZuHgjZ97_3QdTdlUfZYKvA5D8k4tig5nWwdkHdmuqDMKjBwY0Ass-qEI"
}`

// TestJWSSignVerifySelfSigned reproduces issue #54: signing a payload with an
// RSA private JWK and then verifying the produced JWS with the same private JWK
// (self-signed) must succeed. Verification derives the public key internally.
func TestJWSSignVerifySelfSigned(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "jwk.json")
	payloadPath := filepath.Join(dir, "payload.json")
	jwsPath := filepath.Join(dir, "jws.txt")

	if err := os.WriteFile(keyPath, []byte(issueRSAPrivateJWK), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(payloadPath, []byte(`{"sub":"user1"}`), 0600); err != nil {
		t.Fatal(err)
	}

	signer := &jwsSigner{
		Algorithm:     "RS256",
		Key:           keyPath,
		KeyFormat:     "json",
		InputFilePath: payloadPath,
		Output:        jwsPath,
	}
	if err := signer.signer(); err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	jwsMessage, err := os.ReadFile(jwsPath)
	if err != nil {
		t.Fatal(err)
	}

	keyset, err := getKeyFile(keyPath, "json")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("verify with algorithm", func(t *testing.T) {
		t.Parallel()
		verifier := &jwsVerifier{Algorithm: "RS256"}
		var buf bytes.Buffer
		if err := verifier.writeVerifyResult(&buf, jwsMessage, keyset); err != nil {
			t.Fatalf("verify failed: %v", err)
		}
		if got := buf.String(); got != `{"sub":"user1"}` {
			t.Errorf("unexpected payload: %q", got)
		}
	})
}

// signWith signs payload with the key file and algorithm, returning the
// compact JWS as a string.
func signWith(t *testing.T, keyPath, alg, payloadPath, header string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "out.jws")
	s := &jwsSigner{
		Algorithm:     alg,
		Key:           keyPath,
		KeyFormat:     "json",
		Header:        header,
		InputFilePath: payloadPath,
		Output:        out,
	}
	if err := s.valid(); err != nil {
		t.Fatalf("signer valid: %v", err)
	}
	if err := s.signer(); err != nil {
		t.Fatalf("sign failed (%s): %v", alg, err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestJWSSignVerifyRoundTripAcrossAlgorithms(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		keyType string
		curve   string
		size    int
		alg     string
	}{
		{name: "RSA RS256", keyType: "RSA", size: 2048, alg: "RS256"},
		{name: "RSA PS512", keyType: "RSA", size: 2048, alg: "PS512"},
		{name: "EC ES256", keyType: "EC", curve: "P-256", size: 2048, alg: "ES256"},
		{name: "EC ES512", keyType: "EC", curve: "P-521", size: 2048, alg: "ES512"},
		{name: "OKP EdDSA", keyType: "OKP", curve: "Ed25519", size: 2048, alg: "EdDSA"},
		{name: "oct HS256", keyType: "oct", size: 256, alg: "HS256"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			keyPath := genKey(t, tt.keyType, tt.curve, tt.size, "json", false)
			payloadPath := writeFile(t, "payload.txt", "Hello, JOSE!")

			jwsMessage := signWith(t, keyPath, tt.alg, payloadPath, "")

			keyset, err := getKeyFile(keyPath, "json")
			if err != nil {
				t.Fatal(err)
			}
			verifier := &jwsVerifier{Algorithm: tt.alg}
			var buf bytes.Buffer
			if err := verifier.writeVerifyResult(&buf, []byte(jwsMessage), keyset); err != nil {
				t.Fatalf("verify failed: %v", err)
			}
			if got := buf.String(); got != "Hello, JOSE!" {
				t.Errorf("payload mismatch: got %q", got)
			}
		})
	}
}

func TestJWSVerifyWithPublicKeyOnly(t *testing.T) {
	t.Parallel()

	// A message signed with a private EC key must verify against the public
	// JWK derived from it.
	privPath := genKey(t, "EC", "P-256", 2048, "json", false)
	pubPath := genKeyPublicOf(t, privPath)
	payloadPath := writeFile(t, "payload.txt", "public verify")

	jwsMessage := signWith(t, privPath, "ES256", payloadPath, "")

	pubset, err := getKeyFile(pubPath, "json")
	if err != nil {
		t.Fatal(err)
	}
	verifier := &jwsVerifier{Algorithm: "ES256"}
	var buf bytes.Buffer
	if err := verifier.writeVerifyResult(&buf, []byte(jwsMessage), pubset); err != nil {
		t.Fatalf("verify with public key failed: %v", err)
	}
	if buf.String() != "public verify" {
		t.Errorf("payload mismatch: %q", buf.String())
	}
}

func TestJWSVerifyJWKSMultiKeyOnlySecondMatches(t *testing.T) {
	t.Parallel()

	// Regression: a two-key JWK set where only the second key can verify the
	// signature must succeed; the first key failing must not abort the loop.
	k1 := genKey(t, "EC", "P-256", 2048, "json", false)
	k2 := genKey(t, "EC", "P-256", 2048, "json", false)
	payloadPath := writeFile(t, "payload.txt", "second key wins")

	jwsMessage := signWith(t, k2, "ES256", payloadPath, "")

	// Build a public set [k1, k2].
	set := jwk.NewSet()
	for _, p := range []string{k1, k2} {
		ks, err := getKeyFile(p, "json")
		if err != nil {
			t.Fatal(err)
		}
		key, _ := ks.Key(0)
		pub, err := jwk.PublicKeyOf(key)
		if err != nil {
			t.Fatal(err)
		}
		if err := set.AddKey(pub); err != nil {
			t.Fatal(err)
		}
	}

	verifier := &jwsVerifier{Algorithm: "ES256"}
	var buf bytes.Buffer
	if err := verifier.writeVerifyResult(&buf, []byte(jwsMessage), set); err != nil {
		t.Fatalf("multi-key verify failed: %v", err)
	}
	if buf.String() != "second key wins" {
		t.Errorf("payload mismatch: %q", buf.String())
	}
}

func TestJWSVerifyMatchKid(t *testing.T) {
	t.Parallel()

	// match-kid needs a key carrying both "alg" and "kid"; signing injects the
	// kid into the protected header.
	keyPath := octKeyFileWithKid(t, "HS256", "mykey")
	payloadPath := writeFile(t, "payload.txt", "kid matched")

	jwsMessage := signWith(t, keyPath, "HS256", payloadPath, `{"kid":"mykey"}`)

	keyset, err := getKeyFile(keyPath, "json")
	if err != nil {
		t.Fatal(err)
	}
	verifier := &jwsVerifier{MatchKeyID: true}
	var buf bytes.Buffer
	if err := verifier.writeVerifyResult(&buf, []byte(jwsMessage), keyset); err != nil {
		t.Fatalf("match-kid verify failed: %v", err)
	}
	if buf.String() != "kid matched" {
		t.Errorf("payload mismatch: %q", buf.String())
	}
}

func TestJWSVerifyWrongKeyFails(t *testing.T) {
	t.Parallel()

	signKey := genKey(t, "EC", "P-256", 2048, "json", false)
	otherKey := genKey(t, "EC", "P-256", 2048, "json", false)
	payloadPath := writeFile(t, "payload.txt", "data")

	jwsMessage := signWith(t, signKey, "ES256", payloadPath, "")

	keyset, err := getKeyFile(otherKey, "json")
	if err != nil {
		t.Fatal(err)
	}
	verifier := &jwsVerifier{Algorithm: "ES256"}
	var buf bytes.Buffer
	if err := verifier.writeVerifyResult(&buf, []byte(jwsMessage), keyset); !errors.Is(err, ErrVerifyJWSMessage) {
		t.Errorf("expected ErrVerifyJWSMessage, got %v", err)
	}
}

func TestJWSSignValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		signer  *jwsSigner
		wantErr error
	}{
		{
			name:    "missing algorithm",
			signer:  &jwsSigner{Algorithm: "", Key: "k.json", KeyFormat: "json"},
			wantErr: ErrInvalidAlgorithm,
		},
		{
			name:    "missing key",
			signer:  &jwsSigner{Algorithm: "ES256", Key: "", KeyFormat: "json"},
			wantErr: ErrRequireKeyFile,
		},
		{
			name:    "invalid algorithm",
			signer:  &jwsSigner{Algorithm: "FOO", Key: "k.json", KeyFormat: "json"},
			wantErr: ErrInvalidAlgorithm,
		},
		{
			name:    "invalid key format",
			signer:  &jwsSigner{Algorithm: "ES256", Key: "k.json", KeyFormat: "der"},
			wantErr: ErrInvalidKeyFormat,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := tt.signer.valid(); !errors.Is(err, tt.wantErr) {
				t.Errorf("valid() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestJWSParseModes(t *testing.T) {
	t.Parallel()

	const sampleJWS = "eyJhbGciOiJFUzI1NiJ9.SGVsbG8sIFdvcmxkIQ.YP7wVtRe3TxLFkeJ2ei83f67ZT5ajMUSu2GZhTYFeFR5R2yu1vv1emH3ikhBk09czvFFaA41zDBT-KsB1EqphA"

	t.Run("parse inline token prints payload", func(t *testing.T) {
		t.Parallel()
		cmd := newJWSParseCmd()
		p, err := newJWSParser(cmd, []string{sampleJWS})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(p.jws, []byte(sampleJWS)) {
			t.Errorf("inline token not captured")
		}
	})

	t.Run("parse from file", func(t *testing.T) {
		t.Parallel()
		path := writeFile(t, "sample.jws", sampleJWS)
		cmd := newJWSParseCmd()
		p, err := newJWSParser(cmd, []string{path})
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(string(p.jws)) != sampleJWS {
			t.Errorf("file content not read: %q", string(p.jws))
		}
	})

	t.Run("parse without arg errors", func(t *testing.T) {
		t.Parallel()
		cmd := newJWSParseCmd()
		if _, err := newJWSParser(cmd, nil); err == nil {
			t.Error("expected error for missing arg")
		}
	})
}

func TestNewJWSSignerMissingArgs(t *testing.T) {
	t.Parallel()

	cmd := newJWSSignCmd()
	s, err := newJWSSigner(cmd, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.InputFilePath != "" {
		t.Errorf("expected empty input path, got %q", s.InputFilePath)
	}
}
