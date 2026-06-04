package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
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
