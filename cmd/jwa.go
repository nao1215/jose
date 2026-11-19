package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/spf13/cobra"
)

func newJWACmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "jwa",
		Short: "List available algorithms and type",
		RunE:  runJWA,
	}

	cmd.Flags().BoolP("key-type", "k", false, "print JWK key types")
	cmd.Flags().BoolP("elliptic-curve", "e", false, "print elliptic curve types")
	cmd.Flags().BoolP("key-encryption", "K", false, "print key encryption algorithms")
	cmd.Flags().BoolP("content-encryption", "c", false, "print content encryption algorithms")
	cmd.Flags().BoolP("signature", "s", false, "print signature algorithms")
	return cmd
}

type jsonWebAlhorithm struct {
	keyType           bool
	elipticCurve      bool
	keyEncryption     bool
	contentEncryption bool
	signature         bool
}

func newJSONWebAlhorithm(cmd *cobra.Command) (*jsonWebAlhorithm, error) {
	keyType, err := cmd.Flags().GetBool("key-type")
	if err != nil {
		return nil, err
	}

	elipticCurve, err := cmd.Flags().GetBool("elliptic-curve")
	if err != nil {
		return nil, err
	}

	keyEncryption, err := cmd.Flags().GetBool("key-encryption")
	if err != nil {
		return nil, err
	}

	contentEncryption, err := cmd.Flags().GetBool("content-encryption")
	if err != nil {
		return nil, err
	}

	signature, err := cmd.Flags().GetBool("signature")
	if err != nil {
		return nil, err
	}

	return &jsonWebAlhorithm{
		keyType:           keyType,
		elipticCurve:      elipticCurve,
		keyEncryption:     keyEncryption,
		contentEncryption: contentEncryption,
		signature:         signature,
	}, nil
}

func (j *jsonWebAlhorithm) valid() error {
	if !j.keyType && !j.elipticCurve && !j.keyEncryption && !j.contentEncryption && !j.signature {
		return ErrNoOptions
	}
	return nil
}

func (j *jsonWebAlhorithm) writeJWA(w io.Writer) error {
	switch {
	case j.keyType:
		return j.writeKeyTypes(w)
	case j.elipticCurve:
		return j.writeEllipticCurveAlgorithms(w)
	case j.keyEncryption:
		return j.writeKeyEncryptionAlgorithms(w)
	case j.contentEncryption:
		return j.writeContentEncryptionAlgorithms(w)
	case j.signature:
		return j.writeSignatureAlgorithms(w)
	}
	return nil
}

// stringifyAlgorithms converts a slice of jwx algorithm values into their
// string names so they can be intersected with jose's supported lists.
func stringifyAlgorithms[T fmt.Stringer](algs []T) []string {
	names := make([]string, 0, len(algs))
	for _, a := range algs {
		names = append(names, a.String())
	}
	return names
}

func writeLines(w io.Writer, lines []string) error {
	for _, line := range lines {
		if err := writeOutput(w, []byte(line+"\n")); err != nil {
			return err
		}
	}
	return nil
}

func (j *jsonWebAlhorithm) writeKeyTypes(w io.Writer) error {
	return writeLines(w, filterSupported(stringifyAlgorithms(jwa.KeyTypes()), supportedKeyTypes()))
}

func (j *jsonWebAlhorithm) writeEllipticCurveAlgorithms(w io.Writer) error {
	return writeLines(w, filterSupported(stringifyAlgorithms(jwa.EllipticCurveAlgorithms()), supportedEllipticCurves()))
}

func (j *jsonWebAlhorithm) writeKeyEncryptionAlgorithms(w io.Writer) error {
	return writeLines(w, filterSupported(stringifyAlgorithms(jwa.KeyEncryptionAlgorithms()), supportedKeyEncryptionAlgorithms()))
}

func (j *jsonWebAlhorithm) writeContentEncryptionAlgorithms(w io.Writer) error {
	return writeLines(w, filterSupported(stringifyAlgorithms(jwa.ContentEncryptionAlgorithms()), supportedContentEncryptionAlgorithms()))
}

func (j *jsonWebAlhorithm) writeSignatureAlgorithms(w io.Writer) error {
	return writeLines(w, filterSupported(stringifyAlgorithms(jwa.SignatureAlgorithms()), supportedSignatureAlgorithms()))
}

func runJWA(cmd *cobra.Command, _ []string) error {
	jwa, err := newJSONWebAlhorithm(cmd)
	if err != nil {
		return err
	}

	if err := jwa.valid(); err != nil {
		if e := cmd.Usage(); e != nil {
			err = errors.Join(err, e)
		}
		return err
	}

	return jwa.writeJWA(os.Stdout)
}
