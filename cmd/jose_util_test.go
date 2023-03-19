package cmd

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func Test_availableCurves(t *testing.T) {
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
}
