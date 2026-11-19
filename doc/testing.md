# Testing

How jose is tested, the command that runs each kind of test locally, and the CI job that runs it.

| Technique | Files | Local command | CI |
|---|---|---|---|
| Unit tests | `cmd/*_test.go` | `make test` | `unit_test.yml` (Linux, macOS, Windows; Go 1.26.10 and stable; race detector) |
| End-to-end tests | `e2e/atago/*.atago.yaml` | `make e2e` | `e2e_test.yml` (Linux, macOS, Windows) |
| Property-based tests | `cmd/property_test.go` | `go test -run Property ./cmd` | `unit_test.yml` |
| Metamorphic tests | `cmd/metamorphic_test.go` | `go test -run Metamorphic ./cmd` | `unit_test.yml` |
| Differential tests | `cmd/differential_test.go` | `go test -run Differential ./cmd` | `unit_test.yml` |
| Snapshot tests | `e2e/atago/snapshot.atago.yaml`, `e2e/atago/snapshots/` | `make e2e` (`atago snapshot update e2e/atago/snapshot.atago.yaml` rewrites them) | `e2e_test.yml` |
| Fuzzing | `cmd/fuzz_test.go`, `cmd/testdata/fuzz/` | `make test-fuzz FUZZ_TIME=1m` | `fuzz.yml` (20s per target on pull requests, 5m nightly) |
| Mutation testing | `.github/workflows/mutation.yml` | `GOEXPERIMENT=jsonv2 gremlins unleash --workers 2 .` | `mutation.yml` (lines a pull request changes; every package weekly) |
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

## Snapshot tests

The snapshots pin the whole output of the commands whose output depends only on their input: the `jose jwa` lists, `jose jwk public` of fixed keys, `jose jws sign` with EdDSA and HS256 (both deterministic, so the same key and payload give the same token) and `jose jws parse --all`. The keys are throwaway fixtures written by the spec. `.gitattributes` keeps the snapshots LF on Windows, and `.gitleaks.toml` and `trivy-secret.yaml` allow the signed tokens in them.

## Mutation testing

[gremlins](https://github.com/go-gremlins/gremlins) v0.6.0 changes one expression at a time and checks that a test fails. A pull request mutates only the lines it changes; the weekly run mutates every package.

| Date | Killed | Lived | Not covered | Efficacy (killed / (killed + lived)) |
|---|---|---|---|---|
| 2026-11-19 | 242 | 17 | 25 | 93.44% |

Six of the 17 lived mutants negate the check of an output file's `Close` error, which no test can make fail on a regular file; four are in `man.go` (the man page directory and file checks) and one in `version.go` (the build information fallback), which need a real install. The CI job does not gate on the score; a drop below the recorded value is a reason to look at the new lived mutants.
