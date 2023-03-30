package cmd

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestWriteJSON(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		name       string
		v          interface{}
		wantResult string
		wantErr    error
	}{
		{
			name: "simple test",
			v:    map[string]interface{}{"hello": "world"},
			wantResult: `{
    "hello": "world"
}
`,
			wantErr: nil,
		},
		{
			name: "complex test",
			v:    struct{ X, Y int }{X: 1, Y: 2},
			wantResult: `{
    "X": 1,
    "Y": 2
}
`,
			wantErr: nil,
		},
		{
			name:       "invalid input",
			v:          make(chan int),
			wantResult: "",
			wantErr:    ErrSerializeJOSN,
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			buf := new(bytes.Buffer)
			err := writeJSON(buf, tt.v)

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("unexpected error: %v, want: %v", err, tt.wantErr)
			}

			gotResult := buf.String()
			if gotResult != tt.wantResult {
				t.Errorf("mismatch result: got=%s, want=%s", gotResult, tt.wantResult)
			}
		})
	}
}

func TestAvailableCurves(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		want []string
	}{
		{
			name: "Get available curves",
			want: []string{"P-256", "P-384", "P-521"},
		},
	}
	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := availableCurves()
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestOpenOutputFile(t *testing.T) {
	t.Parallel()

	t.Run("Open file", func(t *testing.T) {
		t.Parallel()
		tmpFile := filepath.Join(t.TempDir(), "jose.txt")
		file, err := openOutputFile(tmpFile)
		if err != nil {
			t.Fatal(err)
		}

		want := []byte("test")
		if _, err := file.Write(want); err != nil {
			if e := file.Close(); e != nil {
				err = errors.Join(err, e)
			}
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}

		f, err := os.Open(tmpFile)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
		}()

		got := make([]byte, 4)
		if _, err := f.Read(got); err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(want, got) {
			t.Errorf("mismatch want=%s, got=%s", string(want), string(got))
		}
	})

	t.Run("Failed to open no-exist file", func(t *testing.T) {
		t.Parallel()

		_, err := openOutputFile("")
		if !errors.Is(err, ErrRequireFileName) {
			t.Errorf("Expected error '%v', but got '%v'", ErrRequireFileName, err)
		}
	})
}

func TestOpenInputFile(t *testing.T) {
	t.Parallel()

	t.Run("Open stdin", func(t *testing.T) {
		t.Parallel()

		oldStdin := os.Stdin
		defer func() {
			os.Stdin = oldStdin
		}()

		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("Unexpected error creating pipe: %v", err)
		}
		defer func() {
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
		}()

		want := "Hello World"
		_, err = w.Write([]byte(want))
		if err != nil {
			t.Fatalf("Unexpected error writing to pipe: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}

		os.Stdin = r
		file, err := openInputFile("-")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		defer func() {
			if e := file.Close(); e != nil {
				t.Fatal(e)
			}
		}()

		got, err := io.ReadAll(file)
		if err != nil {
			t.Fatalf("Unexpected error while reading file: %v", err)
		}

		if string(got) != want {
			t.Errorf("Unexpected file content: expected '%s', got '%s'", want, string(got))
		}
	})

	t.Run("Read file", func(t *testing.T) {
		t.Parallel()

		fileName := filepath.Join("testdata", "file", "test.txt")
		file, err := openInputFile(fileName)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		defer func() {
			if e := file.Close(); e != nil {
				t.Fatal(e)
			}
		}()

		got, err := io.ReadAll(file)
		if err != nil {
			t.Errorf("Unexpected error while reading file: %v", err)
		}

		want := "Hello World"
		if string(got) != want {
			t.Errorf("Unexpected file content: expected '%s', got '%s'", want, string(got))
		}
	})

	t.Run("Not specify file name", func(t *testing.T) {
		t.Parallel()

		_, err := openInputFile("")
		if !errors.Is(err, ErrRequireFileName) {
			t.Errorf("Expected error '%v', but got '%v'", ErrRequireFileName, err)
		}
	})
}

func Test_chop(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want string
	}{
		{
			name: "no line feed",
			s:    "no line feed",
			want: "no line feed",
		},
		{
			name: "with \n",
			s:    "with line feed\n",
			want: "with line feed",
		},
		{
			name: "with \r\n",
			s:    "with line feed\r\n",
			want: "with line feed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := chop(tt.s); got != tt.want {
				t.Errorf("chop() = %v, want %v", got, tt.want)
			}
		})
	}
}
