![Coverage](https://raw.githubusercontent.com/nao1215/octocovs-central-repo/main/badges/nao1215/jose/coverage.svg)
![Test Execution Time](https://raw.githubusercontent.com/nao1215/octocovs-central-repo/main/badges/nao1215/jose/time.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/nao1215/jose)](https://goreportcard.com/report/github.com/nao1215/jose)
[![reviewdog](https://github.com/nao1215/jose/actions/workflows/reviewdog.yml/badge.svg)](https://github.com/nao1215/jose/actions/workflows/reviewdog.yml)
[![LinuxUnitTest](https://github.com/nao1215/jose/actions/workflows/linux_test.yml/badge.svg)](https://github.com/nao1215/jose/actions/workflows/linux_test.yml)
[![MacUnitTest](https://github.com/nao1215/jose/actions/workflows/mac_test.yml/badge.svg)](https://github.com/nao1215/jose/actions/workflows/mac_test.yml)
[![WindowsUnitTest](https://github.com/nao1215/jose/actions/workflows/windows.yml/badge.svg)](https://github.com/nao1215/jose/actions/workflows/windows.yml)
[![E2E](https://github.com/nao1215/jose/actions/workflows/e2e_test.yml/badge.svg)](https://github.com/nao1215/jose/actions/workflows/e2e_test.yml)

# jose

jose is a command line tool for JSON Object Signing and Encryption (JOSE). It
generates keys (JWK), signs and verifies messages (JWS), and encrypts and
decrypts messages (JWE) from the shell, so you can work with JOSE without
writing a program. It is built on [github.com/lestrrat-go/jwx](https://github.com/lestrrat-go/jwx)
(MIT license, by lestrrat).

![demo](./doc/img/demo.gif)

## Install

Use `go install`:

```shell
go install github.com/nao1215/jose@latest
```

Use Homebrew:

```shell
brew install nao1215/tap/jose
```

You can also download a prebuilt package (.deb, .rpm, .apk) or binary from the
[release page](https://github.com/nao1215/jose/releases).

Tested on Linux (the main target), macOS, and Windows.

## Quick start

Generate a key, sign a payload, and verify it back:

```shell
$ jose jwk generate --type EC --curve P-256 --output ec.jwk
$ echo '{"sub":"alice"}' > payload.json
$ jose jws sign --algorithm ES256 --key ec.jwk payload.json > token.jws
$ jose jws verify --algorithm ES256 --key ec.jwk token.jws
{"sub":"alice"}
```

Every command reads its input from a file or, when you pass `-`, from standard
input. The `jws parse`, `jws sign`, and `jws verify` commands also accept a JWS
token directly as an argument.

## Generate keys: jose jwk generate

`jose jwk generate` writes a private JWK to standard output, or to a file with
`--output`.

```shell
$ jose jwk generate --type RSA --size 2048
$ jose jwk generate --type EC --curve P-256 --output-format pem
$ jose jwk generate --type OKP --curve Ed25519
$ jose jwk generate --type oct --size 256
$ jose jwk generate --type EC --curve P-256 --public-key
```

Flags:

- `--type` (`-t`): RSA, EC, OKP, or oct. Required.
- `--curve` (`-c`): the elliptic curve. Required for EC and OKP. EC supports
  P-256, P-384, and P-521. OKP supports Ed25519 and X25519.
- `--size` (`-s`): key size in bits. Used by RSA (for example 2048 or 4096) and
  oct (for example 256, which produces a 32 byte secret). It must be a multiple
  of 8 and at least 256. EC and OKP ignore it. The default is 2048.
- `--output-format` (`-O`): json (default) or pem. PEM is available for RSA and
  EC keys; oct keys are JSON only.
- `--output` (`-o`): output file, or `-` for standard output (default).
- `--public-key` (`-p`): emit the public key instead of the private key.

## Sign and verify: jose jws

Sign a payload into a compact JWS:

```shell
$ jose jws sign --algorithm ES256 --key ec.jwk payload.json > token.jws
```

`--algorithm` is required; jose does not pick one for you. Choose it to match
the key (ES256/ES384/ES512 for EC, RS256/PS256 and the like for RSA, EdDSA for
OKP, HS256/HS384/HS512 for oct). Use `--header` to inject extra protected header
fields, for example `--header '{"kid":"my-key"}'`.

Verify a JWS and print the payload:

```shell
$ jose jws verify --algorithm ES256 --key ec.jwk token.jws
{"sub":"alice"}
```

You must provide the algorithm to use, because trusting the `alg` field of the
message itself is unsafe (see [this write-up](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)).
The `--key` file can hold a single JWK or a JWK set; jose tries every key in the
set and succeeds if any one of them verifies the signature. A private JWK works
too: jose derives the public key from it.

As an alternative, `--match-kid` verifies only against the key whose key ID
(`kid`) matches the one named in the message. The matching key must carry both
`alg` and `kid`.

Parse a JWS without verifying it:

```shell
$ jose jws parse token.jws            # print the payload
$ jose jws parse --all token.jws      # print payload, headers, and signature
$ jose jws parse "$(cat token.jws)"   # pass the token as an argument
```

## Encrypt and decrypt: jose jwe

Encrypt a payload into a compact JWE, then decrypt it:

```shell
$ jose jwe encrypt --key ec.jwk --key-encryption ECDH-ES \
    --content-encryption A256GCM payload.json > secret.jwe
$ jose jwe decrypt --key ec.jwk secret.jwe
{"sub":"alice"}
```

Flags for `encrypt`:

- `--key-encryption` (`-K`): how the content key is wrapped, for example
  RSA-OAEP for RSA keys or ECDH-ES for EC keys.
- `--content-encryption` (`-c`): how the payload is encrypted, one of
  A128CBC-HS256, A128GCM, A192CBC-HS384, A192GCM, A256CBC-HS512, A256GCM.
- `--compress` (`-z`): deflate the payload before encrypting.
- `--key-format` (`-F`): json (default) or pem.

`decrypt` reuses `--key`, `--key-encryption`, and `--key-format`. When
`--key-encryption` is omitted, jose reads the algorithm from the message header.

## List algorithms: jose jwa

`jose jwa` prints the algorithm names the underlying library understands, so you
can copy a valid value into the flags above.

```shell
$ jose jwa --key-type            # RSA, EC, OKP, oct
$ jose jwa --elliptic-curve      # curve names
$ jose jwa --signature           # JWS signature algorithms
$ jose jwa --key-encryption      # JWE key encryption algorithms
$ jose jwa --content-encryption  # JWE content encryption algorithms
```

Note that this list is what jwx knows about. jose can generate keys only for the
curves listed under `jose jwk generate` above.

## Helper commands

Shell completion is written to standard output; jose never edits your shell
configuration. Redirect it to wherever your shell loads completions from:

```shell
$ jose completion bash > /etc/bash_completion.d/jose
$ jose completion zsh  > "${fpath[1]}/_jose"
$ jose completion fish > ~/.config/fish/completions/jose.fish
```

Other commands:

- `jose version`: print the version.
- `jose man`: install man pages under /usr/share/man/man1 (needs root).
- `jose bug-report`: open a pre-filled GitHub issue in your browser, including
  your jose version and runtime information.

## Limitations

- jose generates OKP keys for Ed25519 and X25519 only. Ed448 and X448 are not
  supported.
- `jws sign` and `jws verify` work in single key mode.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](./CONTRIBUTING.md) for the
development setup and the local commands that mirror CI (`make test`,
`make test-e2e`, `make test-fuzz`, `make lint`). Security reports are described
in [SECURITY.md](./SECURITY.md), and notable changes are tracked in
[CHANGELOG.md](./CHANGELOG.md).

A GitHub Star motivates continued development.

[![Star History Chart](https://api.star-history.com/svg?repos=nao1215/jose&type=Date)](https://star-history.com/#nao1215/jose&Date)

## Contact

To report a bug or request a feature, open a [GitHub Issue](https://github.com/nao1215/jose/issues),
or run `jose bug-report`.

## License

The jose project is licensed under the [MIT LICENSE](./LICENSE).
