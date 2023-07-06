package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/go-playground/validator/v10"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/nao1215/gorky/file"
	"github.com/spf13/cobra"
)

func newJWSCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "jws",
		Short: "Work with JWS messages",
	}

	cmd.AddCommand(newJWSParseCmd())
	cmd.AddCommand(newJWSSignCmd())
	cmd.AddCommand(newJWSVerifyCmd())
	return cmd
}

func newJWSParseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "parse",
		Short: "Parse JWS mesage",
		Long: `Parse FILE and display information about a JWS message.
Use "-" as FILE to read from STDIN.`,
		RunE: runJWSParse,
	}
	return cmd
}

type jwsParser struct {
	jws []byte `validate:"-"`
}

func newJWSParser(args []string) (*jwsParser, error) {
	if len(args) == 0 {
		return nil, errors.New("you must specify file or jws token")
	}
	inputFilePath := args[0]

	if !file.IsFile(inputFilePath) && inputFilePath != "-" {
		return &jwsParser{jws: []byte(inputFilePath)}, nil
	}

	src, err := openInputFile(inputFilePath)
	if err != nil {
		return nil, err
	}
	defer func() {
		if e := src.Close(); e != nil {
			err = errors.Join(err, e)
		}
	}()

	buf, err := io.ReadAll(src)
	if err != nil {
		return nil, wrap(ErrReadFile, err.Error())
	}
	return &jwsParser{jws: buf}, nil
}

func runJWSParse(_ *cobra.Command, args []string) error {
	jwsParser, err := newJWSParser(args)
	if err != nil {
		return err
	}

	msg, err := jws.Parse(jwsParser.jws)
	if err != nil {
		return wrap(ErrParseMessage, err.Error())
	}
	fmt.Fprintf(os.Stdout, "Payload: %s\n", msg.Payload())

	fmt.Fprint(os.Stdout, "JWS: ")
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
		Use:   "sign",
		Short: "Creates a signed JWS message in compact format from a key and payload.",
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
	var options []jws.SignOption
	options = append(options, jws.WithKey(alg, key))

	if j.Header == "" {
		return options, nil
	}

	h := jws.NewHeaders()
	if err := json.Unmarshal([]byte(j.Header), h); err != nil {
		return nil, wrap(ErrParseHeader, err.Error())
	}
	options = append(options, jws.WithHeaders(h))

	return options, nil
}

func newJWSVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify JWS messages",
		Long: `Parses a JWS message in FILE, and verifies using the specified method.
Use "-" as FILE to read from STDIN.

By default the user is responsible for providing the algorithm to
use to verify the signature. This is because we can not safely rely
on the "alg" field of the JWS message to deduce which key to use.
See https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
 
The alternative is to match a key based on explicitly specified
key ID ("kid"). In this case the following conditions must be met
for a successful verification:

  (1) JWS message must list the key ID that it expects
  (2) At least one of the provided JWK must contain the same key ID
  (3) The same key must also contain the "alg" field 

Therefore, the following key may be able to successfully verify
a JWS message using "--match-kid":

  { "typ": "oct", "alg": "H256", "kid": "mykey", .... }

But the following two will never succeed because they lack
either "alg" or "kid"

  { "typ": "oct", "kid": "mykey", .... }
  { "typ": "oct", "alg": "H256",  .... }
`,
		RunE: runJWSVerify,
	}

	cmd.Flags().StringP("algorithm", "a", "none", "algorithm to use in single key mode")
	cmd.Flags().StringP("key", "k", "", "file name that contains the key to use. single JWK or JWK set")
	cmd.Flags().StringP("key-format", "F", "json", "format of the store key (json/pem)")
	cmd.Flags().BoolP("match-kid", "m", false, "instead of using alg, attempt to verify only if the key ID (kid) matches")
	cmd.Flags().StringP("output", "o", "-", "output to file")

	return cmd
}

type jwsVerifier struct {
	Algorithm     string `validate:"required,oneof=ES256 ES256K ES384 ES512 EdDSA HS256 HS384 HS512 PS256 PS384 PS512 RS256 RS384 RS512 none"`
	Key           string `validate:"required"`
	KeyFormat     string `validate:"oneof=json pem"`
	MatchKeyID    bool   `validate:"-"`
	InputFilePath string `validate:"-"`
	Output        string `validate:"-"`
}

func newJWSVerifier(cmd *cobra.Command, args []string) (*jwsVerifier, error) {
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

	matchKeyID, err := cmd.Flags().GetBool("match-kid")
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

	return &jwsVerifier{
		Algorithm:     algorithm,
		Key:           key,
		KeyFormat:     keyFormat,
		MatchKeyID:    matchKeyID,
		InputFilePath: inputFilePath,
		Output:        output,
	}, nil
}

func (j *jwsVerifier) valid() error {
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

func runJWSVerify(cmd *cobra.Command, args []string) error {
	jwsVerifier, err := newJWSVerifier(cmd, args)
	if err != nil {
		return err
	}

	if err = jwsVerifier.valid(); err != nil {
		return err
	}
	return jwsVerifier.verify()
}

func (j *jwsVerifier) verify() error {
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

	output, err := openOutputFile(j.Output)
	if err != nil {
		return err
	}
	defer func() {
		if e := output.Close(); e != nil {
			err = errors.Join(err, e)
		}
	}()

	return j.writeVerifyResult(output, buf, keyset)
}

func (j *jwsVerifier) writeVerifyResult(w io.Writer, jwsMessage []byte, keyset jwk.Set) error {
	if j.MatchKeyID {
		payload, err := jws.Verify(jwsMessage, jws.WithKeySet(keyset))
		if err != nil {
			return wrap(ErrVerifyJWSMessage, err.Error())
		}
		fmt.Fprintf(w, "%s", payload)
		return nil
	}

	if j.Algorithm == "" {
		return ErrEmptyAlogorithm
	}

	var alg jwa.SignatureAlgorithm
	if err := alg.Accept(j.Algorithm); err != nil {
		return wrap(ErrInvalidAlgorithm, err.Error())
	}

	ctx := context.Background()
	for iter := keyset.Keys(ctx); iter.Next(ctx); {
		pair := iter.Pair()
		key, ok := pair.Value.(jwk.Key)
		if !ok {
			return wrap(ErrVerifyJWSMessage, "type assertion")
		}

		payload, err := jws.Verify(jwsMessage, jws.WithKey(alg, key))
		if err != nil {
			return wrap(ErrVerifyJWSMessage, err.Error())
		}
		fmt.Fprintf(w, "%s", payload)
	}
	return nil
}
