package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/lestrrat-go/jwx/jwa"
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

func (j *jsonWebAlhorithm) writeJWA(w io.Writer) {
	if j.keyType {
		j.writeKeyTypes(w)
		return
	}
	if j.elipticCurve {
		j.writeEllipticCurveAlgorithms(w)
		return
	}
	if j.keyEncryption {
		j.writeKeyEncryptionAlgorithms(w)
		return
	}
	if j.contentEncryption {
		j.writeContentEncryptionAlgorithms(w)
		return
	}
	if j.signature {
		j.writeSignatureAlgorithms(w)
		return
	}
}

func (j *jsonWebAlhorithm) writeKeyTypes(w io.Writer) {
	for _, alg := range jwa.KeyTypes() {
		fmt.Fprintf(w, "%s\n", alg)
	}
}

func (j *jsonWebAlhorithm) writeEllipticCurveAlgorithms(w io.Writer) {
	for _, alg := range jwa.EllipticCurveAlgorithms() {
		fmt.Fprintf(w, "%s\n", alg)
	}
}

func (j *jsonWebAlhorithm) writeKeyEncryptionAlgorithms(w io.Writer) {
	for _, alg := range jwa.KeyEncryptionAlgorithms() {
		fmt.Fprintf(w, "%s\n", alg)
	}
}

func (j *jsonWebAlhorithm) writeContentEncryptionAlgorithms(w io.Writer) {
	for _, alg := range jwa.ContentEncryptionAlgorithms() {
		fmt.Fprintf(w, "%s\n", alg)
	}
}

func (j *jsonWebAlhorithm) writeSignatureAlgorithms(w io.Writer) {
	for _, alg := range jwa.SignatureAlgorithms() {
		fmt.Fprintf(w, "%s\n", alg)
	}
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
		fmt.Println()
		return err
	}

	jwa.writeJWA(os.Stdout)
	return nil
}
