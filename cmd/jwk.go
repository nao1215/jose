package cmd

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwk/jwkbb"
	"github.com/spf13/cobra"
)

func newJWKCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "jwk",
		Short: "JWK is toolset for JSON Web Key",
	}

	cmd.AddCommand(newJWKGenerateCmd())
	cmd.AddCommand(newJWKPublicCmd())
	return cmd
}

func newJWKGenerateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "generate",
		Aliases: []string{"gen"},
		Short:   "Generate a private JWK (JSON Web Key)",
		RunE:    runJWKGenerate,
	}

	cmd.Flags().StringP("curve", "c", "", "elliptic curve for EC (P-256/P-384/P-521) or OKP (Ed25519/X25519) keys")
	cmd.Flags().StringP("type", "t", "", "jwk type (RSA/EC/OKP/oct)")
	cmd.Flags().IntP("size", "s", defaultKeySize, "key size in bits for RSA or oct keys")
	cmd.Flags().StringP("output-format", "O", "json", "output format (json/pem); pem is available for RSA, EC, and OKP Ed25519 keys")
	cmd.Flags().StringP("output", "o", "-", "output to file")
	cmd.Flags().BoolP("public-key", "p", false, "display public key")
	cmd.Flags().String("kid", "", "key ID (kid) to record in the key")
	cmd.Flags().String("alg", "", "algorithm (alg) to record in the key, e.g. ES256 or RSA-OAEP")
	cmd.Flags().String("use", "", "public key use (use) to record in the key: sig or enc")
	cmd.Flags().Bool("set", false, `wrap the key in a JWK Set ({"keys":[...]})`)

	return cmd
}

type jwkGenerater struct {
	Curve        string  `validate:"-"`
	KeyType      string  `validate:"required,oneof=RSA EC OKP oct"`
	KeySize      int     `validate:"-"`
	OutputFormat string  `validate:"oneof=json pem"`
	Output       string  `validate:"-"`
	PublicKey    bool    `validate:"-"`
	KeyID        string  `validate:"-"`
	Algorithm    string  `validate:"-"`
	Use          string  `validate:"-"`
	AsSet        bool    `validate:"-"`
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

	keyID, err := cmd.Flags().GetString("kid")
	if err != nil {
		return nil, err
	}

	algorithm, err := cmd.Flags().GetString("alg")
	if err != nil {
		return nil, err
	}

	use, err := cmd.Flags().GetString("use")
	if err != nil {
		return nil, err
	}

	asSet, err := cmd.Flags().GetBool("set")
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
		KeyID:        keyID,
		Algorithm:    algorithm,
		Use:          use,
		AsSet:        asSet,
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
				e = errors.Join(e, ErrInvalidKeyFormat)
			}
		}
		return e
	}

	if err := j.validKeySize(); err != nil {
		return err
	}

	if err := j.validOct(); err != nil {
		return err
	}

	if err := j.validPemSupport(); err != nil {
		return err
	}

	if err := j.validCurve(); err != nil {
		return err
	}

	return j.validKeyParameters()
}

// validKeyParameters rejects --alg and --use values that the generated key
// could never honor, so jose does not publish a JWK that a relying party would
// refuse later (for example "alg":"ES256" on a P-384 key). PEM cannot carry
// the parameters, so asking for them with PEM output is rejected too.
func (j *jwkGenerater) validKeyParameters() error {
	params := j.keyParameters()
	if j.OutputFormat == "pem" && (!params.empty() || j.AsSet) {
		return ErrKeyParametersForPem
	}
	return params.valid(j.KeyType, j.Curve, j.KeySize)
}

func (j *jwkGenerater) keyParameters() keyParameters {
	return keyParameters{KeyID: j.KeyID, Algorithm: j.Algorithm, Use: j.Use}
}

// keyParameters are the optional JWK parameters (kid, alg, use) that the
// --kid, --alg, and --use flags record in a key.
type keyParameters struct {
	KeyID     string
	Algorithm string
	Use       string
}

func (p keyParameters) empty() bool {
	return p.KeyID == "" && p.Algorithm == "" && p.Use == ""
}

// valid checks the parameters against the key they will be recorded in: a key
// of keyType, with curve for EC and OKP and size in bits for RSA and oct.
func (p keyParameters) valid(keyType, curve string, size int) error {
	if p.Use != "" && p.Use != "sig" && p.Use != "enc" {
		return ErrInvalidKeyUse
	}
	if p.Algorithm == "" {
		return nil
	}

	use, ok := algorithmUse(p.Algorithm)
	if !ok {
		return wrap(ErrInvalidKeyAlgorithm, "input value="+p.Algorithm)
	}
	if p.Use != "" && p.Use != use {
		return wrap(ErrKeyUseMismatch, p.Algorithm+" is for "+use)
	}
	if !algorithmFitsKey(p.Algorithm, keyType, curve, size) {
		described := keyType
		if curve != "" {
			described += " " + curve
		}
		return wrap(ErrKeyAlgorithmMismatch, p.Algorithm+" cannot be used with "+described)
	}
	return nil
}

// setOn records the non-empty parameters in key.
func (p keyParameters) setOn(key jwk.Key) error {
	params := []struct {
		name  string
		value string
	}{
		{jwk.KeyIDKey, p.KeyID},
		{jwk.AlgorithmKey, p.Algorithm},
		{jwk.KeyUsageKey, p.Use},
	}
	for _, param := range params {
		if param.value == "" {
			continue
		}
		if err := key.Set(param.name, param.value); err != nil {
			return wrap(ErrSetKeyParameter, param.name+": "+err.Error())
		}
	}
	return nil
}

// algorithmUse reports whether alg is a signature algorithm ("sig") or a key
// encryption algorithm ("enc") that jose supports.
func algorithmUse(alg string) (string, bool) {
	switch {
	case contains(supportedSignatureAlgorithms(), alg):
		return "sig", true
	case contains(supportedKeyEncryptionAlgorithms(), alg):
		return "enc", true
	}
	return "", false
}

// algorithmFitsKey reports whether a key of keyType (and curve, for EC and OKP,
// or size in bits, for oct) can be used with alg. It follows RFC 7518, which is
// stricter than jwx: each ES algorithm names one curve, and an HMAC key must be
// at least as long as the hash.
func algorithmFitsKey(alg, keyType, curve string, size int) bool {
	switch alg {
	case "ES256":
		return keyType == "EC" && curve == "P-256"
	case "ES384":
		return keyType == "EC" && curve == "P-384"
	case "ES512":
		return keyType == "EC" && curve == "P-521"
	case "EdDSA":
		return keyType == "OKP" && curve == "Ed25519"
	case "HS256":
		return keyType == "oct" && size >= 256
	case "HS384":
		return keyType == "oct" && size >= 384
	case "HS512":
		return keyType == "oct" && size >= 512
	case "A128KW", "A128GCMKW":
		return keyType == "oct" && size == 128
	case "A192KW", "A192GCMKW":
		return keyType == "oct" && size == 192
	case "A256KW", "A256GCMKW":
		return keyType == "oct" && size == 256
	case "PS256", "PS384", "PS512", "RS256", "RS384", "RS512", "RSA-OAEP", "RSA-OAEP-256", "RSA1_5":
		return keyType == "RSA"
	case "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW":
		return keyType == "EC" || (keyType == "OKP" && curve == "X25519")
	}
	// PBES2 treats the key as a password and dir as the content key, whose
	// length depends on the content encryption chosen later.
	return keyType == "oct"
}

// validOct rejects oct-key options that jose cannot honor before the key is
// generated, so the user gets a clear message instead of an internal library
// error. An oct key is a raw symmetric secret: it has no public half, so
// --public-key does not apply.
func (j *jwkGenerater) validOct() error {
	if j.KeyType != jwa.OctetSeq().String() {
		return nil
	}
	if j.PublicKey {
		return ErrPublicKeyForOct
	}
	return nil
}

// validPemSupport rejects PEM output for key types jose cannot frame as X.509,
// so the user gets a clear message instead of an internal encoder error. oct
// keys have no X.509 form, and OKP X25519 maps to Go's crypto/ecdh type, which
// the PEM encoder does not handle.
func (j *jwkGenerater) validPemSupport() error {
	if j.OutputFormat != "pem" {
		return nil
	}
	switch {
	case j.KeyType == jwa.OctetSeq().String():
		return ErrPemForOct
	case j.KeyType == jwa.OKP().String() && j.Curve == "X25519":
		return ErrPemForX25519
	}
	return nil
}

// validKeySize validates --size for the key types that use it. The size is
// expressed in bits and only applies to RSA and oct keys; EC and OKP keys
// ignore it because their length is fixed by the curve.
func (j *jwkGenerater) validKeySize() error {
	if j.KeyType != jwa.RSA().String() && j.KeyType != jwa.OctetSeq().String() {
		return nil
	}
	if j.KeySize < 256 || j.KeySize%8 != 0 {
		return ErrKeySize
	}
	return nil
}

// validCurve validates --curve against the curves jose can actually generate
// for the requested key type. EC keys use P-256/P-384/P-521 and OKP keys use
// Ed25519/X25519; other key types do not use a curve.
func (j *jwkGenerater) validCurve() error {
	switch j.KeyType {
	case jwa.EC().String():
		if j.Curve == "" {
			return ErrRequireCurve
		}
		if !contains(availableCurves(), j.Curve) {
			return wrap(ErrInvalidCurve, "EC supports "+strings.Join(availableCurves(), "/"))
		}
	case jwa.OKP().String():
		if j.Curve == "" {
			return ErrRequireCurve
		}
		if !contains(availableOKPCurves(), j.Curve) {
			return wrap(ErrInvalidCurve, "OKP supports "+strings.Join(availableOKPCurves(), "/"))
		}
	}
	return nil
}

func (j *jwkGenerater) generate() (err error) {
	var rawKey interface{}
	switch j.KeyType {
	case jwa.RSA().String():
		if rawKey, err = j.generateRSA(); err != nil {
			return err
		}
	case jwa.EC().String():
		if rawKey, err = j.generateECDSA(); err != nil {
			return err
		}
	case jwa.OctetSeq().String():
		if rawKey, err = j.generateOctetSeq(); err != nil {
			return err
		}
	case jwa.OKP().String():
		if rawKey, err = j.generateOKP(); err != nil {
			return err
		}
	}

	key, err := jwk.Import[jwk.Key](rawKey)
	if err != nil {
		return wrap(ErrGenerateJWKFromRawKey, err.Error())
	}
	// The parameters go on the private key so that the public key derived
	// from it carries them too.
	if err := j.keyParameters().setOn(key); err != nil {
		return err
	}

	if err := j.KeySet.AddKey(key); err != nil {
		return wrap(ErrGenerateJWKFromRawKey, err.Error())
	}
	if j.PublicKey {
		if err := j.setPublicKey(); err != nil {
			return err
		}
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
	switch j.Curve {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, wrap(ErrInvalidCurve, "EC supports "+strings.Join(availableCurves(), "/"))
	}

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, wrap(ErrGenertateECDSA, err.Error())
	}
	return key, nil
}

func (j *jwkGenerater) generateOctetSeq() (interface{}, error) {
	octets := make([]byte, j.KeySize/8)
	if _, err := rand.Read(octets); err != nil {
		return nil, wrap(ErrGenerateOctetSeq, err.Error())
	}
	return octets, nil
}

func (j *jwkGenerater) generateOKP() (interface{}, error) {
	var rawKey interface{}
	switch j.Curve {
	case "Ed25519":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, wrap(ErrGenerateEd25519, err.Error())
		}
		rawKey = priv
	case "X25519":
		// jwx v4 dropped its x25519 package; X25519 keys now come from the
		// standard library's crypto/ecdh.
		priv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, wrap(ErrGenerateX25519, err.Error())
		}
		rawKey = priv
	default:
		// jwx accepts Ed448/X448 as constants, but Go has no generator for
		// them, so anything other than Ed25519/X25519 is unsupported.
		return nil, wrap(ErrInvalidCurve, "OKP supports "+strings.Join(availableOKPCurves(), "/"))
	}
	return rawKey, nil
}

func (j *jwkGenerater) writeJWKSet(w io.Writer) error {
	switch j.OutputFormat {
	case "pem":
		return j.writeJWKSetByPemFormat(w)
	case "json":
		return writeKeys(w, j.KeySet, j.AsSet)
	default:
		return ErrInvalidKeyFormat
	}
}

func (j *jwkGenerater) writeJWKSetByPemFormat(w io.Writer) error {
	// jwx v4 removed jwk.Pem. PEM encoding now works on raw Go crypto keys, so
	// export the set to raw keys and let jwkbb.EncodePEM frame them as X.509.
	raws, err := jwk.ExportAll[any](j.KeySet)
	if err != nil {
		return wrap(ErrFormatKeyInPem, err.Error())
	}
	buf, err := jwkbb.EncodePEM(raws...)
	if err != nil {
		return wrap(ErrFormatKeyInPem, err.Error())
	}
	if _, err := w.Write(buf); err != nil {
		return wrap(ErrWriteKey, err.Error())
	}
	return nil
}

// writeKeys writes set as JSON. A set holding exactly one key is written as
// that bare key unless asSet is true, so the common single-key case stays a
// plain JWK while --set always yields {"keys":[...]}.
func writeKeys(w io.Writer, set jwk.Set, asSet bool) error {
	if asSet || set.Len() != 1 {
		return writeJSON(w, set)
	}
	key, ok := set.Key(0)
	if !ok {
		return ErrEmptyKey
	}
	return writeJSON(w, key)
}

func runJWKGenerate(cmd *cobra.Command, _ []string) error {
	generator, err := newJWKGenerater(cmd)
	if err != nil {
		return err
	}
	if err := generator.valid(); err != nil {
		return err
	}
	return generator.generate()
}
