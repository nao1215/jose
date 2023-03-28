package cmd

import (
	"errors"
	"fmt"
	"io"

	"github.com/go-playground/validator/v10"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/spf13/cobra"
)

func newJWECmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "jwe",
		Short: "Work with JWE messages",
	}

	cmd.AddCommand(newJWEEncryptCmd())

	return cmd
}

func newJWEEncryptCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt payload to generage JWE message",
		Long: `Encrypt contents of FILE and generate a JWE message using
the specified algorithms and key. Use "-" as FILE to
read from STDIN.		
`,
		RunE: runJWEEncrypt,
	}

	cmd.Flags().StringP("content-encryption", "c", "", "Content encryption algorithm name `NAME` (A128CBC-HS256/A128GCM/A192CBC-HS384/A192GCM/A256CBC-HS512/A256GCM)")
	cmd.Flags().StringP("output", "o", "-", "output to file")
	cmd.Flags().StringP("key", "k", "", "JWK to encrypt with")
	cmd.Flags().StringP("key-encryption", "K", "", "Key encryption algorithm name `NAME` (e.g. RSA-OAEP, ECDH-ES, etc)")
	cmd.Flags().StringP("key-format", "F", "json", "JWK format: json or pem")
	cmd.Flags().BoolP("compress", "z", false, "Enable compression")

	return cmd
}

type jweEncrypter struct {
	Compress          bool   `validate:"-"`
	ContentEncryption string `validate:"oneof=A128CBC-HS256 A128GCM A192CBC-HS384 A192GCM A256CBC-HS512 A256GCM"`
	Key               string `validate:"required"`
	KeyEncryption     string `validate:"required,oneof=A128GCMKW A128KW A192GCMKW A192KW A256GCMKW A256KW ECDH-ES ECDH-ES+A128KW ECDH-ES+A192KW ECDH-ES+A256KW PBES2-HS256+A128KW PBES2-HS384+A192KW PBES2-HS512+A256KW RSA-OAEP RSA-OAEP-256 RSA1_5 dir"`
	KeyFormat         string `validate:"oneof=json pem"`
	InputFilePath     string `validate:"-"`
	Output            string `validate:"-"`
}

func newJWEEncrypter(cmd *cobra.Command, args []string) (*jweEncrypter, error) {
	compress, err := cmd.Flags().GetBool("compress")
	if err != nil {
		return nil, err
	}
	contentEncryption, err := cmd.Flags().GetString("content-encryption")
	if err != nil {
		return nil, err
	}
	key, err := cmd.Flags().GetString("key")
	if err != nil {
		return nil, err
	}
	keyEncryption, err := cmd.Flags().GetString("key-encryption")
	if err != nil {
		return nil, err
	}
	keyFormat, err := cmd.Flags().GetString("key-format")
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

	return &jweEncrypter{
		Compress:          compress,
		ContentEncryption: contentEncryption,
		InputFilePath:     inputFilePath,
		Key:               key,
		KeyEncryption:     keyEncryption,
		KeyFormat:         keyFormat,
		Output:            output,
	}, nil
}

func (j *jweEncrypter) valid() error {
	validate := validator.New()
	if err := validate.Struct(j); err != nil {
		var e error
		for _, v := range err.(validator.ValidationErrors) {
			filedName := v.Field()

			switch filedName {
			case "ContentEncryption":
				e = errors.Join(e, ErrInvalidContentEncryption)
			case "Key":
				e = errors.Join(e, ErrRequireKeyFile)
			case "KeyEncryption":
				e = errors.Join(e, ErrInvalidKeyEncryption)
			case "KeyFormat":
				e = errors.Join(e, ErrInvalidKeyFormat)
			}
		}
		return e
	}
	return nil
}

func runJWEEncrypt(cmd *cobra.Command, args []string) error {
	j, err := newJWEEncrypter(cmd, args)
	if err != nil {
		return err
	}

	if err = j.valid(); err != nil {
		return err
	}

	src, err := openInputFile(j.InputFilePath)
	if err != nil {
		return err
	}
	defer src.Close()

	buf, err := io.ReadAll(src)
	if err != nil {
		return wrap(ErrReadFile, err.Error())
	}

	var keyenc jwa.KeyEncryptionAlgorithm
	if err := keyenc.Accept(j.KeyEncryption); err != nil {
		return wrap(ErrInvalidKeyEncryption, err.Error())
	}

	var contentEncrypt jwa.ContentEncryptionAlgorithm
	if err := contentEncrypt.Accept(j.ContentEncryption); err != nil {
		return wrap(ErrInvalidContentEncryption, err.Error())
	}

	compress := jwa.NoCompress
	if j.Compress {
		compress = jwa.Deflate
	}

	keyset, err := getKeyFile(j.Key, j.KeyFormat)
	if err != nil {
		return err
	}
	if keyset.Len() != 1 {
		return ErrNotContainKey
	}
	key, _ := keyset.Key(0)

	publicKey, err := jwk.PublicKeyOf(key)
	if err != nil {
		return wrap(ErrRetriveKey, fmt.Sprintf("%T: %s", key, err.Error()))
	}

	encrypted, err := jwe.Encrypt(buf, jwe.WithKey(keyenc, publicKey), jwe.WithContentEncryption(contentEncrypt), jwe.WithCompress(compress))
	if err != nil {
		return wrap(ErrEncrypt, err.Error())
	}

	output, err := openOutputFile(j.Output)
	if err != nil {
		return err
	}
	defer output.Close()

	fmt.Fprintf(output, "%s", encrypted)
	return nil
}
