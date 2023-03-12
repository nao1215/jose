package cmd

import "errors"

var (
	ErrEllipticCurveType     = errors.New("elliptic curve type is 'Ed25519', 'Ed448', 'P-256', 'P-384', 'P-521', 'X25519', 'X448'")
	ErrInvalidCurve          = errors.New("invalid elliptic curve")
	ErrKeyType               = errors.New("key type is one of 'RSA', 'EC', 'OKP', 'oct'")
	ErrKeySize               = errors.New("key size must be a multiple of 256 (default = 2048)")
	ErrOutputFormat          = errors.New("invalid output format (only support json or pem)")
	ErrFormatKeyInPem        = errors.New("failed to format key in PEM format")
	ErrWriteKey              = errors.New("failed to write key")
	ErrEmptyKey              = errors.New("key did not exist after key generation")
	ErrSerializeJOSN         = errors.New("failed to serialize to JSON")
	ErrWriteJSON             = errors.New("failed to write JSON")
	ErrCreateFile            = errors.New("failed to create file")
	ErrGenerateRSA           = errors.New("failed to generate RSA private key")
	ErrGenertateECDSA        = errors.New("failed to generate ECDSA private key")
	ErrGenerateEd25519       = errors.New("failed to generate ed25519 private key")
	ErrGenerateX25519        = errors.New("failed to generate X25519 private key")
	ErrGeneratePublicKey     = errors.New("failed to generate public keys")
	ErrGenerateJWKFromRawKey = errors.New("failed to generate new JWK from raw key")
)
