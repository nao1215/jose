package cmd

// This file is the single source of truth for the algorithm names jose can
// actually use. The jwx library knows about more algorithms than jose can
// drive (for example HPKE key encryption, the X448 curve, or the "none"
// signature), so "jose jwa" must report only the subset jose accepts. These
// lists are intersected with what jwx advertises so the output never contains
// a value that another jose subcommand would reject.
//
// The lists must stay in sync with the validator tags on the jws/jwe/jwk
// option structs; algorithm_test.go fails if they drift apart.

// supportedSignatureAlgorithms lists the JWS signature algorithms jose can sign
// and verify with. It matches the validator tags on jwsSigner and jwsVerifier.
func supportedSignatureAlgorithms() []string {
	return []string{
		"ES256", "ES384", "ES512",
		"EdDSA",
		"HS256", "HS384", "HS512",
		"PS256", "PS384", "PS512",
		"RS256", "RS384", "RS512",
	}
}

// supportedKeyEncryptionAlgorithms lists the JWE key encryption algorithms jose
// accepts. It matches the validator tags on jweEncrypter and jweDecrypter.
func supportedKeyEncryptionAlgorithms() []string {
	return []string{
		"A128GCMKW", "A128KW",
		"A192GCMKW", "A192KW",
		"A256GCMKW", "A256KW",
		"ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW",
		"PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW",
		"RSA-OAEP", "RSA-OAEP-256", "RSA1_5",
		"dir",
	}
}

// supportedContentEncryptionAlgorithms lists the JWE content encryption
// algorithms jose accepts. It matches the validator tag on jweEncrypter.
func supportedContentEncryptionAlgorithms() []string {
	return []string{
		"A128CBC-HS256", "A128GCM",
		"A192CBC-HS384", "A192GCM",
		"A256CBC-HS512", "A256GCM",
	}
}

// supportedKeyTypes lists the JWK key types jose can generate. It matches the
// validator tag on jwkGenerater.
func supportedKeyTypes() []string {
	return []string{"RSA", "EC", "OKP", "oct"}
}

// supportedEllipticCurves lists the curves jose can generate: the EC curves
// plus the OKP curves. jwx also advertises X448, which jose cannot generate.
func supportedEllipticCurves() []string {
	curves := append([]string{}, availableCurves()...)
	return append(curves, availableOKPCurves()...)
}

// filterSupported returns the entries of advertised that also appear in
// supported, preserving the order of advertised. It is how "jose jwa" keeps its
// output limited to values jose can really use without inventing names jwx does
// not know.
func filterSupported(advertised []string, supported []string) []string {
	allowed := make(map[string]struct{}, len(supported))
	for _, s := range supported {
		allowed[s] = struct{}{}
	}

	result := make([]string, 0, len(advertised))
	for _, a := range advertised {
		if _, ok := allowed[a]; ok {
			result = append(result, a)
		}
	}
	return result
}
