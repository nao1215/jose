package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/go-playground/validator/v10"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/spf13/cobra"
)

func newJWSCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "jws",
		Short: "Work with JWS messages",
	}

	cmd.AddCommand(newJWSParseCmd())
	cmd.AddCommand(newJWSSignCmd())
	return cmd
}

func newJWSParseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "parse",
		Short: "Parse JWS mesage",
		Long: ` Parse FILE and display information about a JWS message.
Use "-" as FILE to read from STDIN.`,
		RunE: runJWSParse,
	}
	return cmd
}

type jwsParser struct {
	InputFilePath string `validate:"-"`
}

func newJWSParser(args []string) (*jwsParser, error) {
	inputFilePath := ""
	if len(args) != 0 {
		inputFilePath = args[0]
	}

	return &jwsParser{
		InputFilePath: inputFilePath,
	}, nil
}

func runJWSParse(_ *cobra.Command, args []string) error {
	jwsParser, err := newJWSParser(args)
	if err != nil {
		return err
	}

	src, err := openInputFile(jwsParser.InputFilePath)
	if err != nil {
		return err
	}
	defer func() {
		if e := src.Close(); e != nil {
			err = errors.Join(err, e)
		}
	}()

	buf, err := io.ReadAll(src)
	if err != nil {
		return wrap(ErrReadFile, err.Error())
	}

	msg, err := jws.Parse(buf)
	if err != nil {
		return wrap(ErrParseMessage, err.Error())
	}

	if err := writeJSON(os.Stdout, msg); err != nil {
		return err
	}

	for i, sig := range msg.Signatures() {
		fmt.Fprintf(os.Stdout, "Signature %d: ", i)
		if err := writeJSON(os.Stdout, sig.ProtectedHeaders()); err != nil {
			return err
		}
	}
	return nil
}

func newJWSSignCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "sign",
		Aliases: []string{"sig"},
		Short:   "Creates a signed JWS message in compact format from a key and payload.",
		Long: `Signs the payload in FILE and generates a JWS message in compact format.
Use "-" as FILE to read from STDIN.

Currently, only single key signature mode is supported.
`,
		RunE: runJWSSign,
	}

	cmd.Flags().StringP("algorithm", "a", "none", "algorithm to use in single key mode")
	cmd.Flags().StringP("key", "k", "", "file name that contains the key to use. single JWK or JWK set")
	cmd.Flags().StringP("key-format", "F", "json", "format of the store key (json/pem)")
	cmd.Flags().StringP("header", "H", "", "header object to inject into JWS message protected header")
	cmd.Flags().StringP("output", "o", "-", "output to file")

	return cmd
}

type jwsSigner struct {
	Algorithm     string `validate:"required,oneof=ES256 ES256K ES384 ES512 EdDSA HS256 HS384 HS512 PS256 PS384 PS512 RS256 RS384 RS512 none"`
	Key           string `validate:"required"`
	KeyFormat     string `validate:"oneof=json pem"`
	Header        string `validate:"-"`
	InputFilePath string `validate:"-"`
	Output        string `validate:"-"`
}

func newJWSSigner(cmd *cobra.Command, args []string) (*jwsSigner, error) {
	algorithm, err := cmd.Flags().GetString("algorithm")
	if err != nil {
		return nil, err
	}

	key, err := cmd.Flags().GetString("key")
	if err != nil {
		return nil, err
	}

	keyFormat, err := cmd.Flags().GetString("key-format")
	if err != nil {
		return nil, err
	}

	header, err := cmd.Flags().GetString("header")
	if err != nil {
		return nil, err
	}

	inputFilePath := ""
	if len(args) != 0 {
		inputFilePath = args[0]
	}

	output, err := cmd.Flags().GetString("output")
	if err != nil {
		return nil, err
	}

	return &jwsSigner{
		Algorithm:     algorithm,
		Key:           key,
		KeyFormat:     keyFormat,
		Header:        header,
		InputFilePath: inputFilePath,
		Output:        output,
	}, nil
}

func (j *jwsSigner) valid() error {
	validate := validator.New()
	if err := validate.Struct(j); err != nil {
		var e error
		for _, v := range err.(validator.ValidationErrors) {
			filedName := v.Field()

			switch filedName {
			case "Algorithm":
				e = errors.Join(e, ErrInvalidAlgorithm)
			case "Key":
				e = errors.Join(e, ErrRequireKeyFile)
			case "KeyFormat":
				e = errors.Join(e, ErrInvalidKeyFormat)
			}
		}
		return e
	}
	return nil
}

func runJWSSign(cmd *cobra.Command, args []string) error {
	jwsSigner, err := newJWSSigner(cmd, args)
	if err != nil {
		return err
	}

	if err = jwsSigner.valid(); err != nil {
		return err
	}

	return jwsSigner.signer()
}

func (j *jwsSigner) signer() error {
	src, err := openInputFile(j.InputFilePath)
	if err != nil {
		return err
	}
	defer func() {
		if e := src.Close(); e != nil {
			err = errors.Join(err, e)
		}
	}()

	buf, err := io.ReadAll(src)
	if err != nil {
		return wrap(ErrReadFile, err.Error())
	}

	keyset, err := getKeyFile(j.Key, j.KeyFormat)
	if err != nil {
		return err
	}
	if keyset.Len() != 1 {
		return ErrNotContainKey
	}
	key, _ := keyset.Key(0)

	var alg jwa.SignatureAlgorithm
	if err := alg.Accept(j.Algorithm); err != nil {
		return wrap(ErrInvalidAlgorithm, "input value="+j.Algorithm)
	}

	opts, err := j.signOptions(alg, key)
	if err != nil {
		return err
	}

	signed, err := jws.Sign(buf, opts...)
	if err != nil {
		return wrap(ErrSignPayload, err.Error())
	}

	output, err := openOutputFile(j.Output)
	if err != nil {
		return err
	}
	defer func() {
		if e := output.Close(); e != nil {
			err = errors.Join(err, e)
		}
	}()

	fmt.Fprintf(output, "%s", signed)

	return nil
}

func (j *jwsSigner) signOptions(alg jwa.KeyAlgorithm, key interface{}) ([]jws.SignOption, error) {
	if j.Header == "" {
		return []jws.SignOption{}, nil
	}

	var options []jws.SignOption
	h := jws.NewHeaders()
	if err := json.Unmarshal([]byte(j.Header), h); err != nil {
		return nil, wrap(ErrParseHeader, err.Error())
	}
	options = append(options, jws.WithHeaders(h))
	options = append(options, jws.WithKey(alg, key))

	return options, nil
}
