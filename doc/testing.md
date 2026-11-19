# Testing

How jose is tested, the command that runs each kind of test locally, and the CI job that runs it.

| Technique | Files | Local command | CI |
|---|---|---|---|
| Unit tests | `cmd/*_test.go` | `make test` | `unit_test.yml` (Linux, macOS, Windows; Go 1.26.10 and stable; race detector) |
| End-to-end tests | `e2e/atago/*.atago.yaml` | `make e2e` | `e2e_test.yml` (Linux, macOS, Windows) |
| Property-based tests | `cmd/property_test.go` | `go test -run Property ./cmd` | `unit_test.yml` |
| Metamorphic tests | `cmd/metamorphic_test.go` | `go test -run Metamorphic ./cmd` | `unit_test.yml` |
| Differential tests | `cmd/differential_test.go` | `go test -run Differential ./cmd` | `unit_test.yml` |
| Fuzzing | `cmd/fuzz_test.go`, `cmd/testdata/fuzz/` | `make test-fuzz FUZZ_TIME=1m` | `fuzz.yml` (20s per target on pull requests, 5m nightly) |
| Benchmarks | `bench/himorime.yaml` | `make bench`, `make bench-compare` | `bench.yml` (`himorime ci` against the base of the pull request) |

Go 1.26 needs `GOEXPERIMENT=jsonv2` for jwx v4. The make targets set it; set it yourself when you run `go test` directly.

## Property-based tests

The properties use [rapid](https://pkg.go.dev/pgregory.net/rapid). Each one draws 100 inputs per run with a new seed. A failure is shrunk to a small input and prints the seed; `go test -run <Name> ./cmd -rapid.seed=<seed>` replays it, and `-rapid.checks=10000` searches longer.

- Signing then verifying, and encrypting then decrypting, returns the payload for every key type jose generates.
- A token jose signs is recognized as an inline token (`looksLikeCompactJWS`), so `jose jws verify <token>` never reads it as a file name. Three base64url segments are a token only when the first one decodes to JSON.
- `isBase64URL` accepts every unpadded base64url encoding and rejects a string with any other character.

## Differential tests

[go-jose](https://github.com/go-jose/go-jose) is a second JOSE implementation that shares no code with jwx, which jose is built on. It is a test-only dependency.

- go-jose verifies what jose signs and jose verifies what go-jose signs (RS256, RS512, PS256, PS384, ES256, ES384, ES512, EdDSA, HS256, HS512), for payloads drawn by rapid.
- go-jose decrypts what jose encrypts and jose decrypts what go-jose encrypts (RSA-OAEP, RSA-OAEP-256, ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A256KW with GCM and CBC-HMAC content encryption, with and without DEFLATE).
- Both sides read the key from the JWK file jose wrote, and the public key `jose jwk public` derives has the same RFC 7638 thumbprint as the one go-jose derives.
