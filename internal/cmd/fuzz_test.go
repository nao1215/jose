package cmd

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
)

// These fuzz tests feed arbitrary external input into the code paths that parse
// untrusted data. The contract is simply that jose must never panic: any bad
// input has to surface as an error, not a crash.

func FuzzJWSParse(f *testing.F) {
	f.Add([]byte("eyJhbGciOiJFUzI1NiJ9.SGVsbG8sIFdvcmxkIQ.YP7wVtRe3TxLFkeJ"))
	f.Add([]byte(""))
	f.Add([]byte("....."))
	f.Add([]byte("a.b.c"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// jws.Parse must not panic on arbitrary bytes, and a nil error comes
		// with a message.
		msg, err := jws.Parse(data)
		if err == nil && msg == nil {
			t.Fatalf("jws.Parse(%q) returned neither a message nor an error", data)
		}
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

	f.Fuzz(func(t *testing.T, data []byte) {
		v := &jwsVerifier{Algorithm: "ES256"}
		// No input may panic, and none may verify: nothing in the corpus is
		// signed with this freshly generated key.
		if err := v.writeVerifyResult(io.Discard, data, keyset); err == nil {
			t.Fatalf("verified %q, which was not signed with the key", data)
		}
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
	key, ok := keyset.Key(0)
	if !ok {
		f.Fatal("the generated key set is empty")
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		d := &jweDecrypter{}
		// No input may panic, and none may decrypt: nothing in the corpus is
		// encrypted to this freshly generated key.
		if _, err := d.decryptMessage(data, key); err == nil {
			t.Fatalf("decrypted %q, which was not encrypted to the key", data)
		}
	})
}

func FuzzGetKeyFile(f *testing.F) {
	f.Add([]byte(`{"kty":"oct","k":"AAAA"}`))
	f.Add([]byte(`{`))
	f.Add([]byte(``))
	f.Add([]byte(`-----BEGIN PRIVATE KEY-----`))

	dir := f.TempDir()
	path := filepath.Join(dir, "key")

	f.Fuzz(func(t *testing.T, data []byte) {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		// Both formats parse untrusted bytes; neither must panic, and a nil
		// error comes with a key set.
		for _, format := range []string{"json", "pem"} {
			set, err := getKeyFile(path, format)
			if err == nil && set == nil {
				t.Fatalf("getKeyFile(%q, %s) returned neither a key set nor an error", data, format)
			}
		}
	})
}

func FuzzSignOptionsHeader(f *testing.F) {
	f.Add(`{"kid":"abc"}`)
	f.Add(`{`)
	f.Add(`not json`)
	f.Add(``)

	raw := make([]byte, 32)
	key, err := jwk.Import[jwk.Key](raw)
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, header string) {
		s := &jwsSigner{Header: header}
		// A header jose cannot use is reported as ErrParseHeader; any other
		// header yields the one signing option.
		opts, err := s.signOptions(jwa.HS256(), key)
		if err != nil && !errors.Is(err, ErrParseHeader) {
			t.Fatalf("signOptions(%q) failed with %v, want ErrParseHeader", header, err)
		}
		if err == nil && len(opts) != 1 {
			t.Fatalf("signOptions(%q) returned %d options, want 1", header, len(opts))
		}
	})
}
