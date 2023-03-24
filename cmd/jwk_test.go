package cmd

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func Test_newJwkGenerater(t *testing.T) {
	t.Parallel()
	t.Run("Get all options", func(t *testing.T) {
		t.Parallel()

		cmd := newJwkGenerateCmd()
		cmd.Flags().Set("curve", "Ed25519")
		cmd.Flags().Set("type", "RSA")
		cmd.Flags().Set("size", "4096")
		cmd.Flags().Set("output-format", "pem")
		cmd.Flags().Set("output", "test.pem")
		cmd.Flags().Set("public-key", "true")

		got, err := newJwkGenerater(cmd)
		if err != nil {
			t.Fatal(err)
		}

		want := &jwkGenerater{
			Curve:        "Ed25519",
			KeyType:      "RSA",
			KeySize:      4096,
			OutputFormat: "pem",
			Output:       "test.pem",
			PublicKey:    true,
			KeySet:       jwk.NewSet(),
		}

		opt := cmpopts.IgnoreFields(jwkGenerater{}, "KeySet")
		if diff := cmp.Diff(want, got, opt); diff != "" {
			t.Errorf("value is mismatch (-want +got):\n%s", diff)
		}
	})
}
