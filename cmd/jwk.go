package cmd

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/x25519"
	"github.com/spf13/cobra"
)

func newJWKCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "jwk",
		Short: "JWK is toolset for JSON Web Key",
	}

	cmd.AddCommand(newJWKGenerateCmd())
	return cmd
}

func newJWKGenerateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a private JWK (JSON Web Key)",
		RunE:  runGenerate,
	}

	cmd.Flags().StringP("curve", "c", "", "elliptic curve type for EC or OKP keys (Ed25519/Ed448/P-256/P-384/P-521/X25519/X448)")
	cmd.Flags().StringP("type", "t", "", "jwk type (RSA/EC/OKP/oct)")
	cmd.Flags().IntP("size", "s", 2048, "rsa key size or oct key size")
	cmd.Flags().StringP("output-format", "O", "json", "rsa key output format (json/pem)")
	cmd.Flags().StringP("output", "o", "-", "output to file")
	cmd.Flags().BoolP("public-key", "p", false, "display public key")

	return cmd
}

type jwkGenerater struct {
	Curve        string  `validate:"oneof=Ed25519 Ed448 P-256 P-384 P-521 X25519 X448"`
	KeyType      string  `validate:"required,oneof=RSA EC OKP oct"`
	KeySize      int     `validate:"gte=256"`
	OutputFormat string  `validate:"oneof=json pem"`
	Output       string  `validate:"-"`
	PublicKey    bool    `validate:"-"`
	KeySet       jwk.Set `validate:"-"`
}

func newJWKGenerater(cmd *cobra.Command) (*jwkGenerater, error) {
	curve, err := cmd.Flags().GetString("curve")
	if err != nil {
		return nil, err
	}

	keyType, err := cmd.Flags().GetString("type")
	if err != nil {
		return nil, err
	}

	keySize, err := cmd.Flags().GetInt("size")
	if err != nil {
		return nil, err
	}

	outputFormat, err := cmd.Flags().GetString("output-format")
	if err != nil {
		return nil, err
	}

	output, err := cmd.Flags().GetString("output")
	if err != nil {
		return nil, err
	}

	publicKey, err := cmd.Flags().GetBool("public-key")
	if err != nil {
		return nil, err
	}

	keySet := jwk.NewSet()

	return &jwkGenerater{
		Curve:        curve,
		KeyType:      keyType,
		KeySize:      keySize,
		KeySet:       keySet,
		OutputFormat: outputFormat,
		Output:       output,
		PublicKey:    publicKey,
	}, nil
}

func (j *jwkGenerater) valid() error {
	validate := validator.New()
	if err := validate.Struct(j); err != nil {
		var e error
		for _, v := range err.(validator.ValidationErrors) {
			filedName := v.Field()

			switch filedName {
			case "KeyType":
				e = errors.Join(e, ErrKeyType)
			case "KeySize":
				e = errors.Join(e, ErrKeySize)
			case "OutputFormat":
				e = errors.Join(e, ErrOutputFormat)
			}
		}
		return e
	}

	if err := j.validKeySize(); err != nil {
		return err
	}

	return j.validECDSACurve()
}

func (j *jwkGenerater) validKeySize() error {
	if j.KeySize%256 == 0 {
		return nil
	}
	return ErrKeySize
}

func (j *jwkGenerater) validECDSACurve() error {
	if j.KeyType != jwa.EC.String() {
		return nil
	}

	availableCurves()
	return nil
}

func (j *jwkGenerater) generate() (err error) {
	var rawKey interface{}
	switch j.KeyType {
	case jwa.RSA.String():
		if rawKey, err = j.generateRSA(); err != nil {
			return err
		}
	case jwa.EC.String():
		if rawKey, err = j.generateECDSA(); err != nil {
			return err
		}
	case jwa.OctetSeq.String():
		rawKey = j.generateOctetSeq()
	case jwa.OKP.String():
		if rawKey, err = j.generateOKP(); err != nil {
			return err
		}
	}

	key, err := jwk.FromRaw(rawKey)
	if err != nil {
		return wrap(ErrGenerateJWKFromRawKey, err.Error())
	}

	j.KeySet.AddKey(key)
	if j.PublicKey {
		j.setPublicKey()
	}

	output, err := openOutputFile(j.Output)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := output.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	return j.writeJWKSet(output)
}

func (j *jwkGenerater) setPublicKey() error {
	publicKey, err := jwk.PublicSetOf(j.KeySet)
	if err != nil {
		return wrap(ErrGeneratePublicKey, err.Error())
	}
	j.KeySet = publicKey
	return nil
}

func (j *jwkGenerater) generateRSA() (interface{}, error) {
	key, err := rsa.GenerateKey(rand.Reader, j.KeySize)
	if err != nil {
		return nil, wrap(ErrGenerateRSA, err.Error())
	}
	return key, nil
}

func (j *jwkGenerater) generateECDSA() (interface{}, error) {
	var curve elliptic.Curve
	var curveAlogrithm jwa.EllipticCurveAlgorithm
	if err := curveAlogrithm.Accept(j.Curve); err != nil {
		return nil, wrap(fmt.Errorf("%w (ECDSA only support %s)", ErrInvalidCurve, strings.Join(availableCurves(), "/")), err.Error())
	}

	curve, ok := jwk.CurveForAlgorithm(curveAlogrithm)
	if !ok {
		return nil, fmt.Errorf("%w (ECDSA only support %s)", ErrInvalidCurve, strings.Join(availableCurves(), "/"))
	}

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, wrap(ErrGenertateECDSA, err.Error())
	}
	return key, nil
}

func (j *jwkGenerater) generateOctetSeq() interface{} {
	octets := make([]byte, j.KeySize)
	rand.Reader.Read(octets)
	return octets
}

func (j *jwkGenerater) generateOKP() (interface{}, error) {
	var curveAlogrithm jwa.EllipticCurveAlgorithm
	if err := curveAlogrithm.Accept(j.Curve); err != nil {
		return nil, wrap(fmt.Errorf("%w (only support Ed25519/X25519)", ErrInvalidCurve), err.Error())
	}

	var rawKey interface{}
	switch curveAlogrithm {
	case jwa.Ed25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, wrap(ErrGenerateEd25519, err.Error())
		}
		rawKey = priv
	case jwa.X25519:
		_, priv, err := x25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, wrap(ErrGenerateX25519, err.Error())
		}
		rawKey = priv
	}
	return rawKey, nil
}

func (j *jwkGenerater) writeJWKSet(w io.Writer) error {
	switch j.OutputFormat {
	case "pem":
		return j.writeJWKSetByPemFormat(w)
	case "json":
		return j.writeJWKSetByPemByJSONFormat(w)
	default:
		return ErrOutputFormat
	}
}

func (j *jwkGenerater) writeJWKSetByPemFormat(w io.Writer) error {
	buf, err := jwk.Pem(j.KeySet)
	if err != nil {
		return wrap(ErrFormatKeyInPem, err.Error())
	}
	if _, err := w.Write(buf); err != nil {
		return wrap(ErrWriteKey, err.Error())
	}
	return nil
}

func (j *jwkGenerater) writeJWKSetByPemByJSONFormat(w io.Writer) error {
	if j.KeySet.Len() != 1 {
		if err := writeJSON(w, j.KeySet); err != nil {
			return err
		}
	} else {
		key, ok := j.KeySet.Key(0)
		if !ok {
			return ErrEmptyKey
		}
		if err := writeJSON(w, key); err != nil {
			return err
		}
	}
	return nil
}

func runGenerate(cmd *cobra.Command, _ []string) error {
	generator, err := newJWKGenerater(cmd)
	if err != nil {
		return err
	}
	if err := generator.valid(); err != nil {
		return err
	}
	return generator.generate()
}
