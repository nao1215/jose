package cmd

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// failingWriter fails every Write, to exercise the write-error branch of
// writeJSON (ErrWriteJSON) which no happy path reaches.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("boom") }

func TestWriteJSONWriteError(t *testing.T) {
	t.Parallel()
	err := writeJSON(failingWriter{}, map[string]string{"a": "b"})
	if !errors.Is(err, ErrWriteJSON) {
		t.Errorf("want ErrWriteJSON, got %v", err)
	}
}

func TestOpenOutputFileCreateError(t *testing.T) {
	t.Parallel()
	// A path under a directory that does not exist cannot be created.
	bad := filepath.Join(t.TempDir(), "no-such-dir", "key.jwk")
	if _, err := openOutputFile(bad); !errors.Is(err, ErrCreateFile) {
		t.Errorf("want ErrCreateFile, got %v", err)
	}
}

func TestIsBase64URL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want bool
	}{
		{"", true},
		{"abcABC012-_", true},
		{"has space", false},
		{"has.dot", false},
		{"plus+slash/", false},
	}
	for _, tt := range tests {
		if got := isBase64URL(tt.in); got != tt.want {
			t.Errorf("isBase64URL(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestWriteJWKSetMultipleKeys(t *testing.T) {
	t.Parallel()
	// A set holding more than one key exercises the Len() != 1 branch that emits
	// the whole set instead of a bare key.
	set := jwk.NewSet()
	for i := 0; i < 2; i++ {
		raw := make([]byte, 32)
		raw[0] = byte(i + 1)
		key, err := jwk.Import[jwk.Key](raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := set.AddKey(key); err != nil {
			t.Fatal(err)
		}
	}
	g := &jwkGenerater{OutputFormat: "json", KeySet: set}
	var b strings.Builder
	if err := g.writeJWKSet(&b); err != nil {
		t.Fatalf("writeJWKSet: %v", err)
	}
	if !strings.Contains(b.String(), "\"keys\"") {
		t.Errorf("multi-key JSON should contain a keys array:\n%s", b.String())
	}
}

func octSet(t testing.TB, n int) jwk.Set {
	t.Helper()
	set := jwk.NewSet()
	for i := 0; i < n; i++ {
		raw := make([]byte, 32)
		raw[0] = byte(i + 1)
		key, err := jwk.Import[jwk.Key](raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := key.Set(jwk.KeyIDKey, string(rune('a'+i))); err != nil {
			t.Fatal(err)
		}
		if err := set.AddKey(key); err != nil {
			t.Fatal(err)
		}
	}
	return set
}

func TestWriteJWKSetJSONWriteErrorSingleKey(t *testing.T) {
	t.Parallel()
	g := &jwkGenerater{OutputFormat: "json", KeySet: octSet(t, 1)}
	if err := g.writeJWKSet(failingWriter{}); !errors.Is(err, ErrWriteJSON) {
		t.Errorf("want ErrWriteJSON, got %v", err)
	}
}

func TestWriteJWKSetJSONWriteErrorMultiKey(t *testing.T) {
	t.Parallel()
	g := &jwkGenerater{OutputFormat: "json", KeySet: octSet(t, 2)}
	if err := g.writeJWKSet(failingWriter{}); !errors.Is(err, ErrWriteJSON) {
		t.Errorf("want ErrWriteJSON, got %v", err)
	}
}

func TestWriteJWKSetInvalidFormat(t *testing.T) {
	t.Parallel()
	g := &jwkGenerater{OutputFormat: "bogus", KeySet: jwk.NewSet()}
	var b strings.Builder
	if err := g.writeJWKSet(&b); !errors.Is(err, ErrInvalidKeyFormat) {
		t.Errorf("want ErrInvalidKeyFormat, got %v", err)
	}
}

func TestWriteVerifyResultEmptyKeySet(t *testing.T) {
	t.Parallel()
	// An empty key set reaches the "no keys verified" tail of the verify loop.
	v := &jwsVerifier{Algorithm: "ES256"}
	var b strings.Builder
	err := v.writeVerifyResult(&b, []byte("not.a.jws"), jwk.NewSet())
	if !errors.Is(err, ErrVerifyJWSMessage) {
		t.Errorf("want ErrVerifyJWSMessage, got %v", err)
	}
}

func TestGetKeyFileInvalidFormat(t *testing.T) {
	t.Parallel()
	path := writeFile(t, "k.jwk", "{}")
	if _, err := getKeyFile(path, "bogus"); !errors.Is(err, ErrInvalidKeyFormat) {
		t.Errorf("want ErrInvalidKeyFormat, got %v", err)
	}
}

func TestGenerateECDSARejectsUnknownCurve(t *testing.T) {
	t.Parallel()
	g := &jwkGenerater{KeyType: "EC", Curve: "P-999"}
	if _, err := g.generateECDSA(); !errors.Is(err, ErrInvalidCurve) {
		t.Errorf("want ErrInvalidCurve, got %v", err)
	}
}

func TestGenerateOKPRejectsUnknownCurve(t *testing.T) {
	t.Parallel()
	g := &jwkGenerater{KeyType: "OKP", Curve: "Ed448"}
	if _, err := g.generateOKP(); !errors.Is(err, ErrInvalidCurve) {
		t.Errorf("want ErrInvalidCurve, got %v", err)
	}
}

func TestGenerateReportsUnwritableOutput(t *testing.T) {
	t.Parallel()
	g := &jwkGenerater{
		KeyType:      "EC",
		Curve:        "P-256",
		OutputFormat: "json",
		Output:       filepath.Join(t.TempDir(), "no-such-dir", "key.jwk"),
		KeySet:       jwk.NewSet(),
	}
	if err := g.generate(); !errors.Is(err, ErrCreateFile) {
		t.Errorf("want ErrCreateFile, got %v", err)
	}
}

func TestLooksLikeCompactJWSNonBase64Segment(t *testing.T) {
	t.Parallel()
	// Three segments, but the payload holds a character outside the base64url
	// alphabet, so isBase64URL rejects it before any JSON check.
	if looksLikeCompactJWS("eyJhbGciOiJub25lIn0.pay load.sig") {
		t.Error("a segment with a space must not look like a compact JWS")
	}
}

func TestSignerReportsBadHeader(t *testing.T) {
	t.Parallel()
	keyPath := genKey(t, "EC", "P-256", 0, "json", false)
	payload := writeFile(t, "payload.json", `{"sub":"a"}`)
	s := &jwsSigner{
		Algorithm:     "ES256",
		Key:           keyPath,
		KeyFormat:     "json",
		Header:        "{not valid json",
		InputFilePath: payload,
		Output:        "-",
	}
	if err := s.signer(); !errors.Is(err, ErrParseHeader) {
		t.Errorf("want ErrParseHeader, got %v", err)
	}
}

func TestSignerReportsMissingInput(t *testing.T) {
	t.Parallel()
	keyPath := genKey(t, "EC", "P-256", 0, "json", false)
	s := &jwsSigner{
		Algorithm:     "ES256",
		Key:           keyPath,
		KeyFormat:     "json",
		InputFilePath: filepath.Join(t.TempDir(), "no-such-input.json"),
		Output:        "-",
	}
	if err := s.signer(); !errors.Is(err, ErrOpenFile) {
		t.Errorf("want ErrOpenFile, got %v", err)
	}
}

func TestJWEEncryptReportsMissingInput(t *testing.T) {
	t.Parallel()
	keyPath := genKey(t, "EC", "P-256", 0, "json", false)
	e := &jweEncrypter{
		ContentEncryption: "A256GCM",
		Key:               keyPath,
		KeyEncryption:     "ECDH-ES",
		KeyFormat:         "json",
		InputFilePath:     filepath.Join(t.TempDir(), "no-such-input.json"),
		Output:            "-",
	}
	if err := e.encrypt(); !errors.Is(err, ErrOpenFile) {
		t.Errorf("want ErrOpenFile, got %v", err)
	}
}

func TestJWEDecryptReportsCorruptMessage(t *testing.T) {
	t.Parallel()
	keyPath := genKey(t, "EC", "P-256", 0, "json", false)
	corrupt := writeFile(t, "bad.jwe", "this is not a jwe message")
	d := &jweDecrypter{
		Key:           keyPath,
		KeyFormat:     "json",
		InputFilePath: corrupt,
		Output:        "-",
	}
	if err := d.decrypt(); !errors.Is(err, ErrDecrypt) {
		t.Errorf("want ErrDecrypt, got %v", err)
	}
}

func TestPrintAllWriteError(t *testing.T) {
	t.Parallel()
	msg, err := jws.Parse([]byte(sampleJWS))
	if err != nil {
		t.Fatalf("parse sample JWS: %v", err)
	}
	if err := printAll(failingWriter{}, msg); err == nil {
		t.Error("printAll should fail when the writer fails")
	}
}

func TestWriteJWKSetPemWriteError(t *testing.T) {
	t.Parallel()
	// A single EC key encodes to PEM fine; the write to the sink is what fails.
	ecPath := genKey(t, "EC", "P-256", 0, "json", false)
	set, err := getKeyFile(ecPath, "json")
	if err != nil {
		t.Fatal(err)
	}
	g := &jwkGenerater{OutputFormat: "pem", KeySet: set}
	if err := g.writeJWKSet(failingWriter{}); !errors.Is(err, ErrWriteKey) {
		t.Errorf("want ErrWriteKey, got %v", err)
	}
}

func TestEncryptRejectsUnknownKeyEncryption(t *testing.T) {
	t.Parallel()
	keyPath := genKey(t, "EC", "P-256", 0, "json", false)
	payload := writeFile(t, "payload.json", `{"sub":"a"}`)
	e := &jweEncrypter{
		ContentEncryption: "A256GCM",
		Key:               keyPath,
		KeyEncryption:     "BOGUS",
		KeyFormat:         "json",
		InputFilePath:     payload,
		Output:            "-",
	}
	if err := e.encrypt(); !errors.Is(err, ErrInvalidKeyEncryption) {
		t.Errorf("want ErrInvalidKeyEncryption, got %v", err)
	}
}

func TestEncryptRejectsUnknownContentEncryption(t *testing.T) {
	t.Parallel()
	keyPath := genKey(t, "EC", "P-256", 0, "json", false)
	payload := writeFile(t, "payload.json", `{"sub":"a"}`)
	e := &jweEncrypter{
		ContentEncryption: "BOGUS",
		Key:               keyPath,
		KeyEncryption:     "ECDH-ES",
		KeyFormat:         "json",
		InputFilePath:     payload,
		Output:            "-",
	}
	if err := e.encrypt(); !errors.Is(err, ErrInvalidContentEncryption) {
		t.Errorf("want ErrInvalidContentEncryption, got %v", err)
	}
}

func TestDecryptRejectsUnknownExplicitKeyEncryption(t *testing.T) {
	t.Parallel()
	keyPath := genKey(t, "EC", "P-256", 0, "json", false)
	set, err := getKeyFile(keyPath, "json")
	if err != nil {
		t.Fatal(err)
	}
	key, _ := set.Key(0)
	d := &jweDecrypter{Key: keyPath, KeyEncryption: "BOGUS", KeyFormat: "json"}
	if _, err := d.decryptMessage([]byte("ignored"), key); !errors.Is(err, ErrInvalidKeyEncryption) {
		t.Errorf("want ErrInvalidKeyEncryption, got %v", err)
	}
}

func TestEncryptRejectsIncompatibleKey(t *testing.T) {
	t.Parallel()
	// An EC key cannot satisfy the RSA-OAEP key-encryption algorithm, so the
	// underlying encrypt call fails and jose reports it.
	keyPath := genKey(t, "EC", "P-256", 0, "json", false)
	payload := writeFile(t, "payload.json", `{"sub":"a"}`)
	e := &jweEncrypter{
		ContentEncryption: "A256GCM",
		Key:               keyPath,
		KeyEncryption:     "RSA-OAEP",
		KeyFormat:         "json",
		InputFilePath:     payload,
		Output:            "-",
	}
	if err := e.encrypt(); err == nil {
		t.Error("encrypting an EC key with RSA-OAEP should fail")
	}
}

func TestSignerReportsMissingKeyFile(t *testing.T) {
	t.Parallel()
	payload := writeFile(t, "payload.json", `{"sub":"a"}`)
	s := &jwsSigner{
		Algorithm:     "ES256",
		Key:           filepath.Join(t.TempDir(), "no-such-key.jwk"),
		KeyFormat:     "json",
		InputFilePath: payload,
		Output:        "-",
	}
	if err := s.signer(); !errors.Is(err, ErrOpenFile) {
		t.Errorf("want ErrOpenFile, got %v", err)
	}
}

func TestJWEEncryptReportsMissingKeyFile(t *testing.T) {
	t.Parallel()
	payload := writeFile(t, "payload.json", `{"sub":"a"}`)
	e := &jweEncrypter{
		ContentEncryption: "A256GCM",
		Key:               filepath.Join(t.TempDir(), "no-such-key.jwk"),
		KeyEncryption:     "ECDH-ES",
		KeyFormat:         "json",
		InputFilePath:     payload,
		Output:            "-",
	}
	if err := e.encrypt(); !errors.Is(err, ErrOpenFile) {
		t.Errorf("want ErrOpenFile, got %v", err)
	}
}

func TestJWEDecryptReportsMissingKeyFile(t *testing.T) {
	t.Parallel()
	msg := writeFile(t, "c.jwe", "unused")
	d := &jweDecrypter{
		Key:           filepath.Join(t.TempDir(), "no-such-key.jwk"),
		KeyFormat:     "json",
		InputFilePath: msg,
		Output:        "-",
	}
	if err := d.decrypt(); !errors.Is(err, ErrOpenFile) {
		t.Errorf("want ErrOpenFile, got %v", err)
	}
}

func TestWriteVerifyResultEmptyAlgorithm(t *testing.T) {
	t.Parallel()
	keyPath := genKey(t, "EC", "P-256", 0, "json", false)
	set, err := getKeyFile(keyPath, "json")
	if err != nil {
		t.Fatal(err)
	}
	v := &jwsVerifier{Algorithm: ""}
	var b strings.Builder
	if err := v.writeVerifyResult(&b, []byte("x"), set); !errors.Is(err, ErrEmptyAlogorithm) {
		t.Errorf("want ErrEmptyAlogorithm, got %v", err)
	}
}

func TestWriteVerifyResultUnknownAlgorithm(t *testing.T) {
	t.Parallel()
	keyPath := genKey(t, "EC", "P-256", 0, "json", false)
	set, err := getKeyFile(keyPath, "json")
	if err != nil {
		t.Fatal(err)
	}
	v := &jwsVerifier{Algorithm: "BOGUS"}
	var b strings.Builder
	if err := v.writeVerifyResult(&b, []byte("x"), set); !errors.Is(err, ErrInvalidAlgorithm) {
		t.Errorf("want ErrInvalidAlgorithm, got %v", err)
	}
}

func TestNewJWSParserRequiresInputWithoutPipe(t *testing.T) {
	orig := stdinIsPipe
	stdinIsPipe = func() bool { return false }
	defer func() { stdinIsPipe = orig }()

	if _, err := newJWSParser(newJWSParseCmd(), nil); err == nil {
		t.Error("newJWSParser should require input when nothing is piped")
	}
}

func TestGenerateECPropagatesCurveError(t *testing.T) {
	t.Parallel()
	// generate() defends itself even if valid() is bypassed: an EC key with an
	// unknown curve fails at generation.
	g := &jwkGenerater{KeyType: "EC", Curve: "BAD", OutputFormat: "json", Output: "-", KeySet: jwk.NewSet()}
	if err := g.generate(); !errors.Is(err, ErrInvalidCurve) {
		t.Errorf("want ErrInvalidCurve, got %v", err)
	}
}

func TestGenerateOKPPropagatesCurveError(t *testing.T) {
	t.Parallel()
	g := &jwkGenerater{KeyType: "OKP", Curve: "BAD", OutputFormat: "json", Output: "-", KeySet: jwk.NewSet()}
	if err := g.generate(); !errors.Is(err, ErrInvalidCurve) {
		t.Errorf("want ErrInvalidCurve, got %v", err)
	}
}

func TestReadInputRejectsDirectory(t *testing.T) {
	t.Parallel()
	// A directory opens but cannot be read as a byte stream.
	if _, err := readInput(t.TempDir()); !errors.Is(err, ErrReadFile) {
		t.Errorf("want ErrReadFile, got %v", err)
	}
}

func TestReadInputRequiresFileWithoutPipe(t *testing.T) {
	orig := stdinIsPipe
	stdinIsPipe = func() bool { return false }
	defer func() { stdinIsPipe = orig }()
	if _, err := readInput(""); !errors.Is(err, ErrRequireFileName) {
		t.Errorf("want ErrRequireFileName, got %v", err)
	}
}

func TestVerifyReportsMissingKeyFile(t *testing.T) {
	t.Parallel()
	token := writeFile(t, "token.jws", sampleJWS)
	v := &jwsVerifier{
		Algorithm:     "ES256",
		Key:           filepath.Join(t.TempDir(), "missing.jwk"),
		KeyFormat:     "json",
		InputFilePath: token,
		Output:        "-",
	}
	if err := v.verify(); !errors.Is(err, ErrOpenFile) {
		t.Errorf("want ErrOpenFile, got %v", err)
	}
}

func TestResolveVersionAndLine(t *testing.T) {
	orig := Version
	defer func() { Version = orig }()

	Version = "v1.2.3"
	if got := resolveVersion(); got != "v1.2.3" {
		t.Errorf("resolveVersion() = %q, want v1.2.3", got)
	}
	if got := versionLine(); got != "jose version v1.2.3 (under MIT LICENSE)" {
		t.Errorf("versionLine() = %q", got)
	}

	// With no ldflags value, resolveVersion never returns an empty string.
	Version = ""
	if got := resolveVersion(); got == "" {
		t.Error("resolveVersion() returned empty string")
	}
}

// commandWithout copies cmd into a fresh command that declares every flag of
// cmd except drop, keeping the same RunE.
func commandWithout(cmd *cobra.Command, drop string) *cobra.Command {
	stripped := &cobra.Command{Use: cmd.Use, RunE: cmd.RunE}
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if f.Name != drop {
			stripped.Flags().AddFlag(f)
		}
	})
	return stripped
}

// TestRunReportsUndeclaredFlag removes one flag at a time from each command
// and runs it. Every declared flag must be read by the command (a flag that is
// never read would make the run succeed), and a flag that cannot be read must
// stop the run with an error naming that flag instead of falling back to a
// zero value.
func TestRunReportsUndeclaredFlag(t *testing.T) {
	t.Parallel()

	commands := []struct {
		name  string
		build func() *cobra.Command
	}{
		{"jwa", newJWACmd},
		{"jwe encrypt", newJWEEncryptCmd},
		{"jwe decrypt", newJWEDecryptCmd},
		{"jwk generate", newJWKGenerateCmd},
		{"jwk public", newJWKPublicCmd},
		{"jws parse", newJWSParseCmd},
		{"jws sign", newJWSSignCmd},
		{"jws verify", newJWSVerifyCmd},
	}
	for _, c := range commands {
		var names []string
		c.build().Flags().VisitAll(func(f *pflag.Flag) { names = append(names, f.Name) })
		if len(names) == 0 {
			t.Fatalf("%s declares no flags", c.name)
		}
		for _, name := range names {
			t.Run(c.name+" without --"+name+" fails naming the flag", func(t *testing.T) {
				t.Parallel()
				cmd := commandWithout(c.build(), name)
				err := cmd.RunE(cmd, []string{filepath.Join(t.TempDir(), "unused")})
				if err == nil {
					t.Fatal("run succeeded without the flag")
				}
				if want := "flag accessed but not defined: " + name; !strings.HasSuffix(err.Error(), want) {
					t.Errorf("err = %q, want it to end with %q", err, want)
				}
			})
		}
	}
}

func TestRunJWAWithoutOptionsReportsUsageError(t *testing.T) {
	t.Parallel()
	// With no option jwa prints its usage; when printing the usage fails too,
	// both the missing-option error and the usage error reach the caller.
	usageErr := errors.New("usage failed")
	cmd := newJWACmd()
	cmd.SetUsageFunc(func(*cobra.Command) error { return usageErr })
	err := runJWA(cmd, nil)
	if !errors.Is(err, ErrNoOptions) {
		t.Errorf("want ErrNoOptions, got %v", err)
	}
	if !errors.Is(err, usageErr) {
		t.Errorf("want the usage error joined in, got %v", err)
	}
}

func TestWriteJWKSetPemRejectsX25519Key(t *testing.T) {
	t.Parallel()
	// valid() rejects X25519 with PEM output up front; this pins the encoder
	// layer behind it, which must report the failure rather than write
	// anything.
	g := &jwkGenerater{KeyType: "OKP", Curve: "X25519", OutputFormat: "pem", KeySet: jwk.NewSet()}
	raw, err := g.generateOKP()
	if err != nil {
		t.Fatal(err)
	}
	key, err := jwk.Import[jwk.Key](raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.KeySet.AddKey(key); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	if err := g.writeJWKSet(&b); !errors.Is(err, ErrFormatKeyInPem) {
		t.Errorf("want ErrFormatKeyInPem, got %v", err)
	}
	if b.Len() != 0 {
		t.Errorf("nothing should be written on failure, got %q", b.String())
	}
}
