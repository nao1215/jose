package cmd

import (
	"errors"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/spf13/cobra"
)

func newJWKPublicCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "public [FILE...]",
		Short: "Print the public keys of private JWKs",
		Long: `Reads private keys (a JWK, a JWK set, or PEM) from each FILE and prints
their public halves. Use "-" as FILE, or pipe the key in, to read from STDIN.

The key parameters kid, alg, and use are kept, so the output can be published
as-is, for example as the jwks of an OAuth client. Several FILEs are merged
into one set, which is how a new key is published next to an old one during
key rotation. Two keys with the same kid are rejected.

--kid, --alg, and --use label a key that has no such parameters yet, for
example a PEM key made by openssl. They need exactly one input key.`,
		RunE: runJWKPublic,
	}

	cmd.Flags().StringP("key-format", "F", "json", "format of the input keys (json/pem)")
	cmd.Flags().StringP("output", "o", "-", "output to file")
	cmd.Flags().Bool("set", false, `always print a JWK Set ({"keys":[...]}), even for one key`)
	cmd.Flags().String("kid", "", "key ID (kid) to record in the key (one input key only)")
	cmd.Flags().String("alg", "", "algorithm (alg) to record in the key (one input key only)")
	cmd.Flags().String("use", "", "public key use (use) to record in the key: sig or enc (one input key only)")

	return cmd
}

func runJWKPublic(cmd *cobra.Command, args []string) (err error) {
	keyFormat, err := cmd.Flags().GetString("key-format")
	if err != nil {
		return err
	}
	outputPath, err := cmd.Flags().GetString("output")
	if err != nil {
		return err
	}
	asSet, err := cmd.Flags().GetBool("set")
	if err != nil {
		return err
	}
	var params keyParameters
	if params.KeyID, err = cmd.Flags().GetString("kid"); err != nil {
		return err
	}
	if params.Algorithm, err = cmd.Flags().GetString("alg"); err != nil {
		return err
	}
	if params.Use, err = cmd.Flags().GetString("use"); err != nil {
		return err
	}

	if len(args) == 0 {
		args = []string{""}
	}

	public, err := publicKeysOf(args, keyFormat)
	if err != nil {
		return err
	}
	if !params.empty() {
		if err := labelOnlyKey(public, params); err != nil {
			return err
		}
	}

	output, err := openOutputFile(outputPath)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := output.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	return writeKeys(output, public, asSet)
}

// publicKeysOf reads every input, derives the public key of each key in it,
// and merges them into one set in input order.
func publicKeysOf(inputs []string, format string) (jwk.Set, error) {
	public := jwk.NewSet()
	seenKeyIDs := map[string]struct{}{}

	for _, input := range inputs {
		data, err := readInput(input)
		if err != nil {
			return nil, err
		}
		set, err := parseKeySet(data, format)
		if err != nil {
			return nil, err
		}

		for i := range set.Len() {
			key, _ := set.Key(i)
			if key.KeyType() == jwa.OctetSeq() {
				return nil, ErrSymmetricKeyHasNoPublic
			}
			pub, err := jwk.PublicKeyOf(key)
			if err != nil {
				return nil, wrap(ErrGeneratePublicKey, err.Error())
			}
			if kid, ok := pub.KeyID(); ok && kid != "" {
				if _, dup := seenKeyIDs[kid]; dup {
					return nil, wrap(ErrDuplicateKeyID, kid)
				}
				seenKeyIDs[kid] = struct{}{}
			}
			if err := public.AddKey(pub); err != nil {
				return nil, wrap(ErrGeneratePublicKey, err.Error())
			}
		}
	}
	return public, nil
}

// labelOnlyKey records params in the single key of set. Labeling one of
// several keys with the same kid would publish a set that cannot be told
// apart, so more than one key is rejected.
func labelOnlyKey(set jwk.Set, params keyParameters) error {
	if set.Len() != 1 {
		return ErrKeyParametersNeedOneKey
	}
	key, _ := set.Key(0)

	// oct keys never get here (they have no public half), so the size, which
	// only oct algorithms depend on, does not matter.
	keyType, curve := describeJWK(key)
	if err := params.valid(keyType, curve, 0); err != nil {
		return err
	}
	return params.setOn(key)
}

// describeJWK returns the key type and, for EC and OKP keys, the curve of key,
// in the terms algorithmFitsKey takes.
func describeJWK(key jwk.Key) (keyType, curve string) {
	keyType = key.KeyType().String()
	if crv, ok := key.(interface {
		Crv() (jwa.EllipticCurveAlgorithm, bool)
	}); ok {
		if c, ok := crv.Crv(); ok {
			curve = c.String()
		}
	}
	return keyType, curve
}
