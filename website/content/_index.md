---
title: jose
---

jose is a command line tool for JSON Object Signing and Encryption (JOSE). It
generates keys (JWK), publishes key sets (JWKS), signs and verifies messages
(JWS), and encrypts and decrypts messages (JWE), so you can work with JOSE
without writing a program.

![jose generating a key, signing a payload, and verifying it](/img/demo.gif)

## Try it in 30 seconds

Make an ES256 signing key with a key ID, and print the JWKS a verifier would
fetch:

```shell
jose jwk generate --type EC --curve P-256 --kid key-1 --alg ES256 --use sig --output key.jwk
jose jwk public --set key.jwk
```

```json
{
    "keys": [
        {
            "alg": "ES256",
            "crv": "P-256",
            "kid": "key-1",
            "kty": "EC",
            "use": "sig",
            "x": "kA_bU50y_6C9pcVNXru27GpA3ECsV-QZa4OmRyrPWzs",
            "y": "_LKemRUaOxsmX-uZPjTpp0JpvgWv2Ex5CunJHJmD9LQ"
        }
    ]
}
```

`key.jwk` keeps the private key; the printed set holds only the public half,
with the `kid` and `alg` a verifier needs to pick the right key.

## Keys for an atproto OAuth client

A Bluesky / AT Protocol OAuth client that runs on a server authenticates with
`private_key_jwt`, which needs an ES256 key with a `kid` and a published JWKS.
That is these two commands; the
[cookbook recipe](/cookbook/#atproto-oauth-keys-for-a-confidential-client)
walks through the client metadata, a hand-signed client assertion, and key
rotation.

## What jose does

| You want to | Run |
|:--|:--|
| Generate an RSA, EC, OKP, or oct key | `jose jwk generate` |
| Turn private keys into a publishable JWKS | `jose jwk public` |
| Sign a payload or a JWT | `jose jws sign` |
| Verify a signature against a key or a JWKS | `jose jws verify` |
| Decode a token without a key | `jose jws parse` |
| Encrypt and decrypt | `jose jwe encrypt`, `jose jwe decrypt` |
| List the algorithm names jose accepts | `jose jwa` |

Every command reads files, standard input, or a pipe, and writes to standard
output or a file, so jose fits in scripts and CI. The [cookbook](/cookbook/)
has a recipe for each task, and every shell block in it is run by the
end-to-end suite on each commit. The [reference](/reference/) lists every
command and flag.

## Install

```shell
brew install nao1215/tap/jose
```

`go install`, prebuilt binaries, and .deb/.rpm/.apk packages are on the
[install page](/install/).

## Built on jwx

jose is a thin command line layer over
[github.com/lestrrat-go/jwx](https://github.com/lestrrat-go/jwx) (MIT license,
by lestrrat). The cryptography is jwx's; jose adds the command line, the
checks that stop a key from being labeled with an algorithm it cannot serve,
and the tests that keep this documentation true.
