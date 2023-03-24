package cmd

import (
	"bytes"
	"errors"
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
		t.Run(tt.name, func(t *testing.T) {
			got := availableCurves()
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestOpenOutputFile(t *testing.T) {
	t.Parallel()
	t.Run("Open stdout", func(t *testing.T) {
		t.Parallel()
		got, err := openOutputFile("-")
		if err != nil {
			t.Fatal(err)
		}

		want := os.Stdout
		if want != got {
			t.Error("can not open stdout")
		}
	})

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
		if !errors.Is(err, ErrCreateFile) {
			t.Errorf("mismatch want=%v, got=%v", ErrCreateFile, err)
		}
	})
}
