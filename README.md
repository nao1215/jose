<!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->
[![All Contributors](https://img.shields.io/badge/all_contributors-2-orange.svg?style=flat-square)](#contributors-)
<!-- ALL-CONTRIBUTORS-BADGE:END -->
[![CI](https://github.com/nao1215/jose/actions/workflows/unit_test.yml/badge.svg)](https://github.com/nao1215/jose/actions/workflows/unit_test.yml)
[![E2E](https://github.com/nao1215/jose/actions/workflows/e2e_test.yml/badge.svg)](https://github.com/nao1215/jose/actions/workflows/e2e_test.yml)
![Coverage](https://raw.githubusercontent.com/nao1215/octocovs-central-repo/main/badges/nao1215/jose/coverage.svg)
[![Gitleaks](https://github.com/nao1215/jose/actions/workflows/gitleaks.yml/badge.svg)](https://github.com/nao1215/jose/actions/workflows/gitleaks.yml)
[![Trivy](https://github.com/nao1215/jose/actions/workflows/trivy.yml/badge.svg)](https://github.com/nao1215/jose/actions/workflows/trivy.yml)
[![govulncheck](https://github.com/nao1215/jose/actions/workflows/govulncheck.yml/badge.svg)](https://github.com/nao1215/jose/actions/workflows/govulncheck.yml)
[![Gosec](https://github.com/nao1215/jose/actions/workflows/gosec.yml/badge.svg)](https://github.com/nao1215/jose/actions/workflows/gosec.yml)
[![reviewdog](https://github.com/nao1215/jose/actions/workflows/reviewdog.yml/badge.svg)](https://github.com/nao1215/jose/actions/workflows/reviewdog.yml)
[![tested with atago](https://img.shields.io/badge/tested%20with-atago-7c3aed?logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI%2BPHBhdGggZmlsbD0iI2ZmZiIgZD0iTTMuNiA0LjIgMTEuOSAxMmwtOC4zIDcuOC0xLjktMi4yTDcuOSAxMiAxLjcgNi40eiIvPjxyZWN0IGZpbGw9IiNmZmYiIHg9IjEyLjYiIHk9IjE3LjIiIHdpZHRoPSI5LjciIGhlaWdodD0iMi44IiByeD0iMS40Ii8%2BPC9zdmc%2B&logoColor=white)](https://github.com/nao1215/atago)
[![measured with himorime](https://img.shields.io/badge/measured%20with-himorime-d9480f?logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI%2BPHBhdGggZmlsbD0ibm9uZSIgc3Ryb2tlPSIjZmZmIiBzdHJva2Utd2lkdGg9IjIuNCIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBkPSJNNC4yIDE4LjVBOSA5IDAgMSAxIDE5LjggMTguNSIvPjxwYXRoIGZpbGw9Im5vbmUiIHN0cm9rZT0iI2ZmZiIgc3Ryb2tlLXdpZHRoPSIyLjQiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIgZD0iTTEyIDE0LjUgMTYuNSA5Ii8%2BPGNpcmNsZSBmaWxsPSIjZmZmIiBjeD0iMTIiIGN5PSIxNC41IiByPSIyLjIiLz48L3N2Zz4=&logoColor=white)](https://github.com/nao1215/himorime)
[![Go Reference](https://pkg.go.dev/badge/github.com/nao1215/jose.svg)](https://pkg.go.dev/github.com/nao1215/jose)
[![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/nao1215/jose/total)](https://github.com/nao1215/jose/releases)
[![License](https://img.shields.io/github/license/nao1215/jose)](./LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/nao1215/jose/badge)](https://scorecard.dev/viewer/?uri=github.com/nao1215/jose)

# jose

jose is a command line tool for JSON Object Signing and Encryption (JOSE). It
generates keys (JWK), publishes key sets (JWKS), signs and verifies messages
(JWS), and encrypts and decrypts messages (JWE) from the shell. It is built on
[github.com/lestrrat-go/jwx](https://github.com/lestrrat-go/jwx) (MIT license,
by lestrrat).

Documentation: https://nao1215.github.io/jose/ ([cookbook](https://nao1215.github.io/jose/cookbook/), [reference](https://nao1215.github.io/jose/reference/))

![demo](./doc/img/demo.gif)

## Install

```shell
brew install nao1215/tap/jose
```

Or build from source with Go 1.26.10 or later. jwx v4 uses `encoding/json/v2`,
which Go 1.26 still keeps behind `GOEXPERIMENT=jsonv2`:

```shell
GOEXPERIMENT=jsonv2 go install github.com/nao1215/jose@latest
```

Prebuilt binaries and .deb/.rpm/.apk packages are on the
[release page](https://github.com/nao1215/jose/releases). jose is tested on
Linux (the main target), macOS, and Windows.
Releases after v0.4.1 sign `checksums.txt` with cosign and ship an SPDX SBOM
and SLSA build provenance; the commands that verify them are in
[Verifying release integrity](https://nao1215.github.io/jose/install/#verifying-release-integrity).

## Quick start

Generate a key, sign a payload, and verify it back:

```shell
jose jwk generate --type EC --curve P-256 --output ec.jwk
echo '{"sub":"alice"}' | jose jws sign --algorithm ES256 --key ec.jwk > token.jws
jose jws verify --algorithm ES256 --key ec.jwk token.jws
```

Every command that reads a message or a key file also takes `-` or a pipe, and
`jws parse` and `jws verify` take a token inline:

![pipe](./doc/img/pipe.gif)

Make an ES256 key with a key ID, and print the JWKS a verifier would fetch:

```shell
jose jwk generate --type EC --curve P-256 --kid key-1 --alg ES256 --use sig --output key.jwk
jose jwk public --set key.jwk
```

Those two commands are also what a Bluesky / AT Protocol OAuth confidential
client needs for `private_key_jwt`. The cookbook recipe
[atproto OAuth: keys for a confidential client](https://nao1215.github.io/jose/cookbook/#atproto-oauth-keys-for-a-confidential-client)
covers the client metadata, a hand-signed client assertion, and key rotation.

## What jose does

| You want to | Run |
|:--|:--|
| Generate an RSA, EC, OKP, or oct key, optionally with `kid`, `alg`, and `use` | `jose jwk generate` |
| Turn private keys (JWK or PEM) into a publishable JWKS | `jose jwk public` |
| Sign a payload or a JWT | `jose jws sign` |
| Verify against a key or a JWKS, by algorithm or by `kid` | `jose jws verify` |
| Decode a token without a key | `jose jws parse` |
| Encrypt and decrypt | `jose jwe encrypt`, `jose jwe decrypt` |
| List the algorithm names jose accepts | `jose jwa` |

Results go to standard output or `--output`, and errors go to standard error
with exit status 1. The
[reference](https://nao1215.github.io/jose/reference/) lists every flag.

Apart from the install commands and the website's install page, the end-to-end suite ([atago](https://github.com/nao1215/atago)
specs under `e2e/atago/`) runs every shell block in this README, on the website,
and in the cookbook word for word, and `internal/cmd/docs_test.go` fails when a
block is left out.

## Testing

| Technique | Bug class caught here |
|---|---|
| [Unit tests](internal/cmd) | Wrong flag handling, key parameters and errors on Linux, macOS and Windows |
| [End-to-end tests](e2e/atago) | Changed output and exit codes of the real `jose` binary, and README or cookbook commands that stopped working |
| [Property-based tests](internal/cmd/property_test.go) | Sign/verify and encrypt/decrypt round trips that fail for some payload, and inline tokens mistaken for file names |
| [Metamorphic tests](internal/cmd/metamorphic_test.go) | Input paths (file, `-`, pipe, inline token) or private and public keys that give different results |
| [Differential tests](internal/cmd/differential_test.go) | Signatures, ciphertexts and JWKs that another JOSE implementation (go-jose) does not accept |
| [Snapshot tests](e2e/atago/snapshot.atago.yaml) | Unintended changes to the algorithm lists, the JSON layout of a key, or a deterministic signature |
| [Fuzzing](internal/cmd/fuzz_test.go) | Panics on malformed tokens, key files and `--header` values |
| [Mutation testing](.github/workflows/mutation.yml) | Tests that run changed code without checking its result |
| [Benchmarks](bench) | Slower key generation, signing and encryption, measured against the base of each pull request |

The commands and CI jobs for each are in [doc/testing.md](doc/testing.md).

## Contributing

Contributions are welcome. [CONTRIBUTING.md](./CONTRIBUTING.md) has the
development setup and the local commands that mirror CI (`make test`,
`make e2e`, `make test-fuzz`, `make lint`, `make website`). See
[SECURITY.md](./SECURITY.md) for security reports and
[CHANGELOG.md](./CHANGELOG.md) for changes.

A GitHub Star motivates continued development.

[![Star History Chart](https://api.star-history.com/svg?repos=nao1215/jose&type=Date)](https://star-history.com/#nao1215/jose&Date)

## Contributors ✨

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/en/reference/emoji-key/)):

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tbody>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="http://www.elza.ru/"><img src="https://avatars.githubusercontent.com/u/20461314?v=4?s=64" width="64px;" alt="M.Onyshchuk"/><br /><sub><b>M.Onyshchuk</b></sub></a><br /><a href="https://github.com/nao1215/jose/issues?q=author%3Am-onyshchuk" title="Bug reports">🐛</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://debimate.jp/"><img src="https://avatars.githubusercontent.com/u/22737008?v=4?s=64" width="64px;" alt="CHIKAMATSU Naohiro"/><br /><sub><b>CHIKAMATSU Naohiro</b></sub></a><br /><a href="https://github.com/nao1215/jose/commits?author=nao1215" title="Code">💻</a> <a href="https://github.com/nao1215/jose/commits?author=nao1215" title="Documentation">📖</a></td>
    </tr>
  </tbody>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome!

## Contact

To report a bug or request a feature, open a [GitHub Issue](https://github.com/nao1215/jose/issues),
or run `jose bug-report`.

## License

The jose project is licensed under the [MIT LICENSE](./LICENSE).
