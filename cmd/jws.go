package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/go-playground/validator/v10"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
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
		Short: "Parse a JWS message and print its payload",
		Long: `Parse JWS and display payload in the JWS message.
Use "-" as FILE to read from STDIN.`,
		RunE: runJWSParse,
	}
	cmd.Flags().BoolP("all", "a", false, "print all information (payload, header, signature)")
	return cmd
}

type jwsParser struct {
	jws []byte `validate:"-"`
	all bool   `validate:"-"`
}

func newJWSParser(cmd *cobra.Command, args []string) (*jwsParser, error) {
	if len(args) == 0 {
		return nil, errors.New("you must specify file or jws token")
	}
	inputFilePath := args[0]

	all, err := cmd.Flags().GetBool("all")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "can not parse command line argument (payload", err)
	}

	var jws []byte
	if !file.IsFile(inputFilePath) && inputFilePath != "-" {
		jws = []byte(inputFilePath)
	} else {
		src, err := openInputFile(inputFilePath)
		if err != nil {
			return nil, err
		}
		defer func() {
			if e := src.Close(); e != nil {
				err = errors.Join(err, e)
			}
		}()
		jws, err = io.ReadAll(src)
		if err != nil {
			return nil, wrap(ErrReadFile, err.Error())
		}
	}

	return &jwsParser{
		jws: jws,
		all: all,
	}, nil
}

func runJWSParse(cmd *cobra.Command, args []string) error {
	jwsParser, err := newJWSParser(cmd, args)
	if err != nil {
		return err
	}

	msg, err := jws.Parse(jwsParser.jws)
	if err != nil {
		return wrap(ErrParseMessage, err.Error())
	}

	if jwsParser.all {
		return printAll(msg)
	}
	fmt.Fprintf(os.Stdout, "%s", string(msg.Payload()))
	return nil
}

// printAll prints all information about JWS message. It prints payload, header and signature.
func printAll(msg *jws.Message) error {
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

	cmd.Flags().StringP("algorithm", "a", "", "signature algorithm (required, e.g. ES256, RS256, HS256, EdDSA)")
	cmd.Flags().StringP("key", "k", "", "file name that contains the key to use. single JWK or JWK set")
	cmd.Flags().StringP("key-format", "F", "json", "format of the store key (json/pem)")
	cmd.Flags().StringP("header", "H", "", "header object to inject into JWS message protected header")
	cmd.Flags().StringP("output", "o", "-", "output to file")

	return cmd
}

type jwsSigner struct {
	Algorithm     string `validate:"required,oneof=ES256 ES384 ES512 EdDSA HS256 HS384 HS512 PS256 PS384 PS512 RS256 RS384 RS512"`
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

	alg, ok := jwa.LookupSignatureAlgorithm(j.Algorithm)
	if !ok {
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
	// v4 moved protected headers into a sub-option of WithKey instead of a
	// standalone SignOption.
	var subopts []jws.WithKeySuboption
	if j.Header != "" {
		h := jws.NewHeaders()
		if err := json.Unmarshal([]byte(j.Header), h); err != nil {
			return nil, wrap(ErrParseHeader, err.Error())
		}
		subopts = append(subopts, jws.WithProtectedHeaders(h))
	}

	return []jws.SignOption{jws.WithKey(alg, key, subopts...)}, nil
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

	cmd.Flags().StringP("algorithm", "a", "", "signature algorithm (required, e.g. ES256, RS256, HS256, EdDSA)")
	cmd.Flags().StringP("key", "k", "", "file name that contains the key to use. single JWK or JWK set")
	cmd.Flags().StringP("key-format", "F", "json", "format of the store key (json/pem)")
	cmd.Flags().BoolP("match-kid", "m", false, "instead of using alg, attempt to verify only if the key ID (kid) matches")
	cmd.Flags().StringP("output", "o", "-", "output to file")

	return cmd
}

type jwsVerifier struct {
	Algorithm     string `validate:"required_without=MatchKeyID,omitempty,oneof=ES256 ES384 ES512 EdDSA HS256 HS384 HS512 PS256 PS384 PS512 RS256 RS384 RS512"`
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
		// A JWS message signed with a private key must be verified with the
		// corresponding public key. When the user supplies a private JWK (the
		// self-signed case), derive the public keys so verification succeeds.
		// v4 rejects symmetric keys in PublicSetOf by default; allow them so a
		// match-kid verification with an oct (HMAC) key still works.
		pubset, err := jwk.PublicSetOf(keyset, jwk.WithAllowSymmetric(true))
		if err != nil {
			return wrap(ErrVerifyJWSMessage, err.Error())
		}

		payload, err := jws.Verify(jwsMessage, jws.WithKeySet(pubset))
		if err != nil {
			return wrap(ErrVerifyJWSMessage, err.Error())
		}
		fmt.Fprintf(w, "%s", payload)
		return nil
	}

	if j.Algorithm == "" {
		return ErrEmptyAlogorithm
	}

	alg, ok := jwa.LookupSignatureAlgorithm(j.Algorithm)
	if !ok {
		return wrap(ErrInvalidAlgorithm, j.Algorithm)
	}

	// Try every key in the set. A JWK set may legitimately hold several keys
	// where only one matches the signature, so a failure on one key must not
	// abort verification: keep going until a key verifies, and only report an
	// error when none of them do.
	var lastErr error
	for _, key := range keyset.All() {
		// Verify with the public key. PublicKeyOf returns the key as-is for
		// symmetric keys and the public counterpart for private keys, so a
		// self-signed message created from a private JWK verifies correctly.
		pubkey, err := jwk.PublicKeyOf(key)
		if err != nil {
			lastErr = wrap(ErrVerifyJWSMessage, err.Error())
			continue
		}

		payload, err := jws.Verify(jwsMessage, jws.WithKey(alg, pubkey))
		if err != nil {
			lastErr = wrap(ErrVerifyJWSMessage, err.Error())
			continue
		}
		fmt.Fprintf(w, "%s", payload)
		return nil
	}

	if lastErr == nil {
		lastErr = wrap(ErrVerifyJWSMessage, "key set contains no keys")
	}
	return lastErr
}
