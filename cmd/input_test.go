package cmd

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

// withStdinPipe replaces os.Stdin with a pipe carrying data and forces
// stdinIsPipe to report a pipe, restoring both when the test ends.
func withStdinPipe(t *testing.T, data string) {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(data)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	oldStdin := os.Stdin
	oldPipe := stdinIsPipe
	os.Stdin = r
	stdinIsPipe = func() bool { return true }

	t.Cleanup(func() {
		os.Stdin = oldStdin
		stdinIsPipe = oldPipe
		_ = r.Close()
	})
}

// sampleJWS is a compact JWS used across the input tests.
const sampleJWS = "eyJhbGciOiJFUzI1NiJ9.SGVsbG8sIFdvcmxkIQ.YP7wVtRe3TxLFkeJ2ei83f67ZT5ajMUSu2GZhTYFeFR5R2yu1vv1emH3ikhBk09czvFFaA41zDBT-KsB1EqphA"

func TestLooksLikeCompactJWS(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want bool
	}{
		{name: "real compact JWS", in: sampleJWS, want: true},
		{name: "missing-file typo with one dot", in: "does-not-exist.jws", want: false},
		{name: "dotted file name a.b.c", in: "a.b.c", want: false},
		{name: "plain file name", in: "token.jws", want: false},
		{name: "two dots but header not JSON", in: "abc.def.ghi", want: false},
		{name: "empty header", in: ".payload.sig", want: false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := looksLikeCompactJWS(tt.in); got != tt.want {
				t.Errorf("looksLikeCompactJWS(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestReadCompactJWSInlineToken(t *testing.T) {
	t.Parallel()

	got, err := readCompactJWS(sampleJWS)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(got, []byte(sampleJWS)) {
		t.Errorf("inline token not returned verbatim: %q", got)
	}
}

func TestReadCompactJWSMissingFileReportsOpenError(t *testing.T) {
	t.Parallel()

	// A typo that is not token-shaped must surface as a file-open error, not a
	// parse error.
	_, err := readCompactJWS("does-not-exist.jws")
	if !errors.Is(err, ErrOpenFile) {
		t.Errorf("expected ErrOpenFile for a missing file, got %v", err)
	}
}

func TestReadCompactJWSFromFile(t *testing.T) {
	t.Parallel()

	path := writeFile(t, "token.jws", sampleJWS)
	got, err := readCompactJWS(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != sampleJWS {
		t.Errorf("file content mismatch: %q", got)
	}
}

func TestReadCompactJWSFromPipe(t *testing.T) {
	withStdinPipe(t, sampleJWS)

	got, err := readCompactJWS("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != sampleJWS {
		t.Errorf("piped token mismatch: %q", got)
	}
}

func TestReadInputFromPipe(t *testing.T) {
	withStdinPipe(t, "piped payload")

	got, err := readInput("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != "piped payload" {
		t.Errorf("piped payload mismatch: %q", got)
	}
}

func TestOpenInputFileEmptyWithoutPipe(t *testing.T) {
	// Without a pipe, an empty path still asks for a file name.
	oldPipe := stdinIsPipe
	stdinIsPipe = func() bool { return false }
	t.Cleanup(func() { stdinIsPipe = oldPipe })

	if _, err := openInputFile(""); !errors.Is(err, ErrRequireFileName) {
		t.Errorf("expected ErrRequireFileName, got %v", err)
	}
}

// TestReadInputReadsAll is a small guard that readInput drains the reader.
func TestReadInputReadsAll(t *testing.T) {
	t.Parallel()

	path := writeFile(t, "payload.txt", "hello world")
	got, err := readInput(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello world" {
		t.Errorf("readInput mismatch: %q", got)
	}
}
