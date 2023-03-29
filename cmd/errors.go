package cmd

import (
	"errors"
	"fmt"
)

var (
	ErrNoOptions                = errors.New("no options specified")
	ErrRequireFileName          = errors.New(`filename required (use "-" to read from stdin)`)
	ErrOpenFile                 = errors.New("failed to open file")
	ErrReadFile                 = errors.New("failed to read file")
	ErrEllipticCurveType        = errors.New("elliptic curve type is 'Ed25519', 'Ed448', 'P-256', 'P-384', 'P-521', 'X25519', 'X448'")
	ErrInvalidCurve             = errors.New("invalid elliptic curve")
	ErrRequireKeyFile           = errors.New("key file required (you must specify --key option)")
	ErrKeyType                  = errors.New("key type is one of 'RSA', 'EC', 'OKP', 'oct'")
	ErrKeySize                  = errors.New("key size must be a multiple of 256 (default = 2048)")
	ErrInvalidKeyFormat         = errors.New("invalid output format (only support json or pem)")
	ErrInvalidKeyEncryption     = errors.New("invalid key encryption; the supported key encryption can be checked with '$jose jwa -K'")
	ErrInvalidContentEncryption = errors.New("content encryption is one of 'A128CBC-HS256', 'A128GCM', 'A192CBC-HS384', 'A192GCM', 'A256CBC-HS512', 'A256GCM'")
	ErrFormatKeyInPem           = errors.New("failed to format key in PEM format")
	ErrWriteKey                 = errors.New("failed to write key")
	ErrEmptyKey                 = errors.New("key did not exist after key generation")
	ErrNotContainKey            = errors.New("jwk file must contain exactly one key")
	ErrParseKey                 = errors.New("failed to parse key")
	ErrRetriveKey               = errors.New("failed to retrieve public key")
	ErrSerializeJOSN            = errors.New("failed to serialize to JSON")
	ErrWriteJSON                = errors.New("failed to write JSON")
	ErrCreateFile               = errors.New("failed to create file")
	ErrEncrypt                  = errors.New("failed to encrypt message")
	ErrDecrypt                  = errors.New("failed to decrypt message")
	ErrGenerateRSA              = errors.New("failed to generate RSA private key")
	ErrGenertateECDSA           = errors.New("failed to generate ECDSA private key")
	ErrGenerateEd25519          = errors.New("failed to generate ed25519 private key")
	ErrGenerateX25519           = errors.New("failed to generate X25519 private key")
	ErrGeneratePublicKey        = errors.New("failed to generate public keys")
	ErrGenerateJWKFromRawKey    = errors.New("failed to generate new JWK from raw key")
)

// wrap return wrapping error with message.
// If e is nil, return new error with msg. If msg is empty string, return e.
func wrap(e error, msg string) error {
	if e == nil {
		return errors.New(msg)
	}
	if msg == "" {
		return e
	}
	return fmt.Errorf("%w: %s", e, msg)
}
