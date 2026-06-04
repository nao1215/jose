# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and per-release binaries and notes are published from git tags by GoReleaser.

## [Unreleased]

## [0.2.0] - 2026-06-05

### Added

- Pipe support: `jws sign`, `jws verify`, `jws parse`, and `jwe encrypt`/`decrypt`
  now read standard input when input is piped, so no explicit `-` is needed
  (for example `echo ... | jose jws sign ...`).
- `jws verify` accepts a compact JWS token directly as its argument, like
  `jws parse` already did.

### Fixed

- `jose jwa` now lists only the algorithms, curves, and key types jose actually
  accepts. Values the jwx library advertises but jose rejects (the `none` and
  `Ed25519` signatures, the `X448` curve, `RSA-OAEP-384`/`RSA-OAEP-512` and the
  HPKE key encryptions, the `AKP` key type) are filtered out.
- `jws parse` and `jws verify` no longer treat a mistyped file name as a JWS
  token. A value that is not shaped like a compact JWS is opened as a file, so a
  typo reports "failed to open file" instead of a confusing parse error.
- `jwk generate` rejects unsupported option combinations up front with a clear
  message instead of surfacing an internal library error: `--output-format pem`
  for `oct` and OKP `X25519` keys, and `--public-key` for `oct` keys.

### Changed

- Migrated from jwx v2 (and the stray jwx v1 import in `jwa`) to jwx v4. The
  module now requires Go 1.26. Because jwx v4 uses `encoding/json/v2`, building
  jose from source requires `GOEXPERIMENT=jsonv2` until that package leaves the
  experiment; the `make` targets, CI, and GoReleaser set it, and the README and
  CONTRIBUTING note it for `go install`.
- Internal adjustments for the v4 API: `jwa` algorithm constants are now
  functions, `jwk.FromRaw`/`Raw` became `jwk.Import`/`jwk.Export`, PEM output
  goes through `jwkbb.EncodePEM`, key files are read with `jwk.Parse` and
  `jwk.WithX509`, JWK sets are iterated with `Set.All()`, and X25519 keys are
  generated with the standard library's `crypto/ecdh` (jwx dropped its `x25519`
  package). `jws sign`/`verify` dropped ES256K from the accepted algorithms,
  since it now lives in a separate jwx extension module. Behavior and CLI flags
  are unchanged.

## [0.1.0] - 2026-06-05

This is the first release after a project-wide review. It fixes the commands
whose documented behavior did not match the implementation, makes the unsafe
defaults explicit, and adds a thorough test suite.

### Fixed

- `jwk generate` no longer advertises curves it cannot produce. The Ed448 and
  X448 OKP curves are rejected with a clear message instead of failing deep in
  the key generation with `jwk.FromRaw requires a non-nil key`. EC keys now
  validate the curve (P-256/P-384/P-521) and require one.
- `jwk generate --size` is documented and validated as a bit length for RSA and
  oct keys. `--size 256` now produces a 32 byte oct secret, matching the unit in
  the help text (previously the size was used as a byte count).
- Output files are truncated before writing, so overwriting a long key, JWS, or
  JWE with a shorter one no longer leaves trailing garbage that breaks parsing.
- `jws verify` with a JWK set now tries every key and succeeds if any one of them
  verifies the signature, instead of giving up after the first key fails.
- `bug-report` now includes OS, architecture, Go version, and jose version, and
  its Markdown headers are no longer broken with stray `**`.

### Changed

- `jws sign` and `jws verify` no longer default `--algorithm` to `none`. The
  algorithm is now required (verify can instead use `--match-kid`), so a missing
  algorithm fails fast with a clear message rather than producing a confusing
  signing error.
- `completion` now takes an explicit shell (`completion bash|zsh|fish`) and
  writes the script to stdout. It no longer generates all three scripts at once,
  writes files under your home directory, or edits `.zshrc`. Errors from
  generating a completion script are propagated.
- The README and the per-command help were rewritten to be task-oriented:
  install, quick start, key generation, sign/verify, encrypt/decrypt, helper
  commands, and limitations, with a demo at the top. Several typos were fixed.

### Added

- A demo GIF generated with vhs, shown near the top of the README.
- A comprehensive unit test suite covering the normal, error, and regression
  paths for `jwk`, `jws`, `jwe`, `completion`, and `bug-report`.
- Property-based, metamorphic, and fuzz tests for the key generation, signing,
  encryption, and parsing paths.
- Shellspec end-to-end tests under `spec/` that drive the built binary, run in CI
  on Linux and macOS, and are reproducible locally with `make test-e2e`.
- `SECURITY.md`, `CONTRIBUTING.md`, and this `CHANGELOG.md`.
- `make test-e2e`, `make test-fuzz`, and `make demo` targets, and `Fuzz` and
  `E2E` GitHub Actions workflows. The unit-test workflows now pin the Go version
  to `go.mod`.

## [0.0.8] - earlier

Pre-review development releases (0.0.1 through 0.0.8). See the git history and
the [release page](https://github.com/nao1215/jose/releases) for details.

[Unreleased]: https://github.com/nao1215/jose/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/nao1215/jose/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/nao1215/jose/compare/v0.0.8...v0.1.0
[0.0.8]: https://github.com/nao1215/jose/releases/tag/v0.0.8
