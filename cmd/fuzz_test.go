package cmd

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// These fuzz tests feed arbitrary external input into the code paths that parse
// untrusted data. The contract is simply that jose must never panic: any bad
// input has to surface as an error, not a crash.

func FuzzJWSParse(f *testing.F) {
	f.Add([]byte("eyJhbGciOiJFUzI1NiJ9.SGVsbG8sIFdvcmxkIQ.YP7wVtRe3TxLFkeJ"))
	f.Add([]byte(""))
	f.Add([]byte("....."))
	f.Add([]byte("a.b.c"))

	f.Fuzz(func(_ *testing.T, data []byte) {
		// jws.Parse must not panic on arbitrary bytes.
		_, _ = jws.Parse(data)
	})
}

func FuzzJWSVerify(f *testing.F) {
	f.Add([]byte("not a jws"))
	f.Add([]byte("a.b.c"))

	keyPath := genKey(f, "EC", "P-256", 2048, "json", false)
	keyset, err := getKeyFile(keyPath, "json")
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(_ *testing.T, data []byte) {
		v := &jwsVerifier{Algorithm: "ES256"}
		// Discard output; we only care that it does not panic.
		_ = v.writeVerifyResult(io.Discard, data, keyset)
	})
}

func FuzzJWEDecrypt(f *testing.F) {
	f.Add([]byte("not a jwe"))
	f.Add([]byte("a.b.c.d.e"))

	keyPath := genKey(f, "RSA", "", 2048, "json", false)
	keyset, err := getKeyFile(keyPath, "json")
	if err != nil {
		f.Fatal(err)
	}
	key, _ := keyset.Key(0)

	f.Fuzz(func(_ *testing.T, data []byte) {
		d := &jweDecrypter{}
		_, _ = d.decryptMessage(data, key)
	})
}

func FuzzGetKeyFile(f *testing.F) {
	f.Add([]byte(`{"kty":"oct","k":"AAAA"}`))
	f.Add([]byte(`{`))
	f.Add([]byte(``))
	f.Add([]byte(`-----BEGIN PRIVATE KEY-----`))

	dir := f.TempDir()
	path := filepath.Join(dir, "key")

	f.Fuzz(func(_ *testing.T, data []byte) {
		if err := os.WriteFile(path, data, 0600); err != nil {
			return
		}
		// Both formats parse untrusted bytes; neither must panic.
		_, _ = getKeyFile(path, "json")
		_, _ = getKeyFile(path, "pem")
	})
}

func FuzzSignOptionsHeader(f *testing.F) {
	f.Add(`{"kid":"abc"}`)
	f.Add(`{`)
	f.Add(`not json`)
	f.Add(``)

	raw := make([]byte, 32)
	key, err := jwk.FromRaw(raw)
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(_ *testing.T, header string) {
		s := &jwsSigner{Header: header}
		_, _ = s.signOptions(jwa.HS256, key)
	})
}
