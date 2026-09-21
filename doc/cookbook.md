# Cookbook

Copyable jose recipes, indexed by task. Every recipe runs as shown: the shell
blocks on this page are executed word for word by the end-to-end suite
(`e2e/atago/cookbook.atago.yaml`), so a command you copy from here is one that
worked on the last commit.

The recipes are written for a POSIX shell (bash, zsh). On Windows, run them in
Git Bash or WSL. A few recipes also call `openssl` to show interoperability or
to make a random ID; jose itself does not need it.

## Find a recipe by task

| I want to | Go to |
|:--|:--|
| Make a new key | [Generate a key](#generate-a-key) |
| Give a key an ID and pin its algorithm | [Label a key with kid, alg, and use](#label-a-key-with-kid-alg-and-use) |
| Hand out the public half of a key | [Get the public key](#get-the-public-key) |
| Publish a JWKS and rotate keys in it | [Publish a JWKS and rotate keys](#publish-a-jwks-and-rotate-keys) |
| Set up keys for a Bluesky / atproto OAuth confidential client | [atproto OAuth: keys for a confidential client](#atproto-oauth-keys-for-a-confidential-client) |
| Build a DPoP proof to see what one looks like | [Build a DPoP proof by hand](#build-a-dpop-proof-by-hand) |
| Sign a JWT and check it against a JWKS | [Sign and verify a JWT](#sign-and-verify-a-jwt) |
| Read a token without a key | [Inspect a token without verifying it](#inspect-a-token-without-verifying-it) |
| Sign with a shared secret | [Sign with a shared secret (HMAC)](#sign-with-a-shared-secret-hmac) |
| Send something only one party can read | [Encrypt for someone's public key](#encrypt-for-someones-public-key) |
| Encrypt with a key both sides hold | [Encrypt with a shared key](#encrypt-with-a-shared-key) |
| Use a key that openssl made | [Use PEM keys from openssl](#use-pem-keys-from-openssl) |
| Know which algorithm goes with which key | [Pick an algorithm for a key](#pick-an-algorithm-for-a-key) |
| Call jose from a script or CI | [Script it](#script-it) |

## Generate a key

An EC P-256 private key, written to a file:

```shell
jose jwk generate --type EC --curve P-256 --output ec.jwk
```

```json
{
    "crv": "P-256",
    "d": "KylPmPC2EVBmU_lz3c9NTs6bmcklx2WBMP4RUQU0y3E",
    "kty": "EC",
    "x": "t744xDfTyMIL3TZlaA7AqZtyjcjD6KiGw6CZQWYO5Ec",
    "y": "6mmDgCl_uYekeXGM9D6JtxdHsAqDZj560JJTb5fTPcE"
}
```

The other key types:

```shell
jose jwk generate --type RSA --size 3072 --output rsa.jwk
jose jwk generate --type OKP --curve Ed25519 --output ed25519.jwk
jose jwk generate --type oct --size 256 --output secret.jwk
```

The same key as PEM, for tools that want PEM. An EC key comes out as SEC 1
(`EC PRIVATE KEY`); RSA and Ed25519 keys come out as PKCS #8 (`PRIVATE KEY`):

```shell
jose jwk generate --type EC --curve P-256 --output-format pem --output ec.pem
```

A file written with `--output` is created readable by its owner only, since it
holds a private key:

```shell
ls -l ec.jwk
```

Without `--output`, the key goes to standard output.

## Label a key with kid, alg, and use

`--kid`, `--alg`, and `--use` record the key ID, the algorithm, and the purpose
in the key itself:

```shell
jose jwk generate --type EC --curve P-256 --kid key-1 --alg ES256 --use sig --output signing.jwk
```

```json
{
    "alg": "ES256",
    "crv": "P-256",
    "d": "OTuEtDRDl84aZKuH5Q3O5SBX4HW1R8QkjA6CeIFlwVw",
    "kid": "key-1",
    "kty": "EC",
    "use": "sig",
    "x": "kA_bU50y_6C9pcVNXru27GpA3ECsV-QZa4OmRyrPWzs",
    "y": "_LKemRUaOxsmX-uZPjTpp0JpvgWv2Ex5CunJHJmD9LQ"
}
```

Why bother:

- `kid` lets a verifier holding several keys pick the right one. `jose jws sign`
  copies it into the token header for you.
- `alg` pins the key to one algorithm, so it cannot be used with another.
  `jose jws verify --match-kid` needs both `kid` and `alg`.
- `use` says whether the key signs (`sig`) or encrypts (`enc`).

jose refuses a label the key could never honor, such as ES256 on a P-384 key
(ES256 means P-256), or `--use enc` with a signature algorithm. The command
exits with status 1 and writes nothing:

```shell
jose jwk generate --type EC --curve P-384 --alg ES256 --output wrong.jwk || echo "rejected"
```

## Get the public key

`jose jwk public` drops the private parts of a key and keeps `kid`, `alg`, and
`use`:

```shell
jose jwk public signing.jwk > signing.pub.jwk
```

`--set` wraps the result in a JWK Set (`{"keys":[...]}`), the shape a JWKS
endpoint serves:

```shell
jose jwk public --set signing.jwk > jwks.json
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

`--public-key` on `jwk generate` prints only the public half of a new key, which
is useful when the private half is not needed at all:

```shell
jose jwk generate --type EC --curve P-256 --public-key
```

A symmetric (oct) key has no public half, so `jwk public` refuses it.

## Publish a JWKS and rotate keys

A JWKS is a JWK Set of public keys served at a URL (a `jwks_uri`). Build it from
the private keys you sign with; every key needs a distinct `kid` so a verifier
can find the right one:

```shell
jose jwk generate --type EC --curve P-256 --kid key-1 --alg ES256 --use sig --output key-1.jwk
jose jwk public --set key-1.jwk > jwks.json
```

To rotate, add the new key next to the old one, start signing with the new one,
and drop the old one once nothing signed by it is still in use. Several files
merge into one set, in order:

```shell
jose jwk generate --type EC --curve P-256 --kid key-2 --alg ES256 --use sig --output key-2.jwk
jose jwk public --set key-1.jwk key-2.jwk > jwks.json
```

Later, publish only the new key:

```shell
jose jwk public --set key-2.jwk > jwks.json
```

Two keys with the same `kid` are rejected rather than published side by side.

## atproto OAuth: keys for a confidential client

A Bluesky / AT Protocol OAuth client that runs on a server is a confidential
client. It authenticates to the Authorization Server with `private_key_jwt`: it
signs a short JWT (the client assertion) with its own private key, and the
server checks it against the public keys the client publishes in its client
metadata. The [atproto OAuth specification](https://atproto.com/specs/oauth)
asks for:

- at least one public key, published as `jwks_uri` (a URL serving a JWKS) or
  inline as `jwks`, not both;
- ES256, the recommended and most widely supported algorithm, which means an EC
  P-256 key;
- a `kid` on every key, because an auth session stays bound to the key (its
  `kid`, `alg`, and thumbprint) that started it;
- `token_endpoint_auth_method` set to `private_key_jwt`.

Generate the private key. The `kid` is yours to choose; a date or a counter
makes rotation easy to follow:

```shell
jose jwk generate --type EC --curve P-256 --alg ES256 --use sig --kid key-1 --output client-key-1.jwk
```

Build the public JWKS from it:

```shell
jose jwk public --set client-key-1.jwk > jwks.json
```

Serve `jwks.json` over HTTPS and point the client metadata at it. The fields
that concern the key are `jwks_uri`, `token_endpoint_auth_method`, and
`token_endpoint_auth_signing_alg`:

```json
{
    "client_id": "https://app.example.com/oauth/client-metadata.json",
    "application_type": "web",
    "client_name": "Example App",
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "redirect_uris": ["https://app.example.com/oauth/callback"],
    "scope": "atproto transition:generic",
    "dpop_bound_access_tokens": true,
    "token_endpoint_auth_method": "private_key_jwt",
    "token_endpoint_auth_signing_alg": "ES256",
    "jwks_uri": "https://app.example.com/oauth/jwks.json"
}
```

Give the private key to your OAuth library, for example through an environment
variable. The key file is plain JSON, so it fits in one:

```shell
PRIVATE_KEY_1="$(cat client-key-1.jwk)"
export PRIVATE_KEY_1
```

The official Node.js client, `@atproto/oauth-client-node`, loads it with
`JoseKey.fromImportable(process.env.PRIVATE_KEY_1, 'key-1')` and serves the
JWKS itself from `client.jwks`, so with that library you keep the private key
and let it publish `jwks.json`. With a library or stack that does not, publish
the file jose built above.

To see what the library sends, sign a client assertion by hand. Its `iss` and
`sub` are your `client_id`, `aud` is the Authorization Server's issuer, and
`jti` must be unique. jose puts the key's `kid` in the header:

```shell
client_id="https://app.example.com/oauth/client-metadata.json"
issuer="https://bsky.social"
now=$(date +%s)
printf '{"iss":"%s","sub":"%s","aud":"%s","jti":"%s","iat":%s,"exp":%s}' \
  "$client_id" "$client_id" "$issuer" "$(openssl rand -hex 16)" "$now" "$((now + 60))" |
  jose jws sign --algorithm ES256 --key client-key-1.jwk --header '{"typ":"JWT"}' > client-assertion.jwt
```

Check it the way the server does, by `kid` against the published JWKS:

```shell
jose jws verify --match-kid --key jwks.json client-assertion.jwt
```

```text
{"iss":"https://app.example.com/oauth/client-metadata.json","sub":"https://app.example.com/oauth/client-metadata.json","aud":"https://bsky.social","jti":"8c3f2b6e0d9a4f7e1b5c2a6d9e0f3b7a","iat":1789993809,"exp":1789993869}
```

jose checks the signature only. The claims (`aud`, `exp`, and so on) are the
server's to judge.

Rotate the key as in [Publish a JWKS and rotate keys](#publish-a-jwks-and-rotate-keys):
publish `key-2` next to `key-1`, use `key-2` for new sessions, and remove
`key-1` once no session started with it is still alive:

```shell
jose jwk generate --type EC --curve P-256 --alg ES256 --use sig --kid key-2 --output client-key-2.jwk
jose jwk public --set client-key-1.jwk client-key-2.jwk > jwks.json
```

## Build a DPoP proof by hand

atproto OAuth also binds every token to a DPoP key: each request carries a
fresh proof JWT whose header holds the public key (`jwk`) and whose claims name
the request. OAuth libraries create these per session; building one by hand
shows what goes into it. Use a separate key, never the client key:

```shell
jose jwk generate --type EC --curve P-256 --alg ES256 --output dpop.jwk
```

```shell
now=$(date +%s)
printf '{"jti":"%s","htm":"POST","htu":"%s","iat":%s}' \
  "$(openssl rand -hex 16)" "https://bsky.social/oauth/par" "$now" |
  jose jws sign --algorithm ES256 --key dpop.jwk \
    --header "{\"typ\":\"dpop+jwt\",\"jwk\":$(jose jwk public dpop.jwk)}" > dpop.jwt
```

The header carries the public key only, never `d`:

```shell
jose jws parse --all dpop.jwt
```

## Sign and verify a JWT

A JWT signed with ES256 is a compact JWS whose payload is a JSON object of
claims. Make a labeled key and the JWKS your verifiers will fetch:

```shell
jose jwk generate --type EC --curve P-256 --kid api-1 --alg ES256 --output api.jwk
jose jwk public --set api.jwk > jwks.json
```

Sign the claims:

```shell
printf '{"sub":"alice","iat":%s}' "$(date +%s)" |
  jose jws sign --algorithm ES256 --key api.jwk --header '{"typ":"JWT"}' > token.jwt
```

Verify with the algorithm you expect. jose never takes the algorithm from the
token's own `alg` header, which the sender controls; trusting it is what makes
algorithm-confusion attacks possible:

```shell
jose jws verify --algorithm ES256 --key jwks.json token.jwt
```

Or let the token's `kid` choose the key from the set. The key must carry both
`kid` and `alg`:

```shell
jose jws verify --match-kid --key jwks.json token.jwt
```

A token signed by any other key fails with exit status 1:

```shell
jose jwk generate --type EC --curve P-256 --kid other --alg ES256 --output other.jwk
jose jwk public --set other.jwk > other-jwks.json
jose jws verify --algorithm ES256 --key other-jwks.json token.jwt || echo "not trusted"
```

## Inspect a token without verifying it

`jws parse` decodes a token without any key. Use it to read, never to trust:

```shell
jose jws parse token.jwt
```

`--all` adds the headers, which is where `alg`, `kid`, and `typ` live:

```shell
jose jws parse --all token.jwt
```

A token can be passed inline, for example one copied from an `Authorization`
header:

```shell
token=$(cat token.jwt)
jose jws parse "$token"
```

## Sign with a shared secret (HMAC)

When the signer and the verifier are the same party, or share a secret, HS256
over a 256-bit oct key is enough:

```shell
jose jwk generate --type oct --size 256 --kid shared-1 --alg HS256 --output hmac.jwk
echo '{"sub":"alice"}' | jose jws sign --algorithm HS256 --key hmac.jwk > hmac.jws
jose jws verify --algorithm HS256 --key hmac.jwk hmac.jws
```

HS384 needs a key of at least 384 bits, and HS512 one of at least 512 bits;
jose rejects `--alg HS512` on a 256-bit key.

## Encrypt for someone's public key

The recipient makes a key pair and hands out the public half:

```shell
jose jwk generate --type EC --curve P-256 --alg ECDH-ES+A256KW --use enc --output recipient.jwk
jose jwk public recipient.jwk > recipient.pub.jwk
```

The sender encrypts with the public key:

```shell
echo 'meet at noon' | jose jwe encrypt --key recipient.pub.jwk \
  --key-encryption ECDH-ES+A256KW --content-encryption A256GCM > message.jwe
```

Only the private key opens it. `decrypt` reads the key encryption algorithm
from the message:

```shell
jose jwe decrypt --key recipient.jwk message.jwe
```

```text
meet at noon
```

The same with RSA:

```shell
jose jwk generate --type RSA --size 3072 --alg RSA-OAEP-256 --use enc --output rsa-recipient.jwk
jose jwk public rsa-recipient.jwk > rsa-recipient.pub.jwk
echo 'meet at noon' | jose jwe encrypt --key rsa-recipient.pub.jwk \
  --key-encryption RSA-OAEP-256 --content-encryption A256GCM > rsa-message.jwe
jose jwe decrypt --key rsa-recipient.jwk rsa-message.jwe
```

## Encrypt with a shared key

A 256-bit oct key wraps the content key with A256KW. `--compress` deflates the
payload first:

```shell
jose jwk generate --type oct --size 256 --alg A256KW --use enc --output aes.jwk
echo 'meet at noon' | jose jwe encrypt --key aes.jwk \
  --key-encryption A256KW --content-encryption A256GCM --compress > shared.jwe
jose jwe decrypt --key aes.jwk shared.jwe
```

## Use PEM keys from openssl

Every command that takes a key reads PEM with `--key-format pem`, so a key made
by openssl works as it is:

```shell
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa.pem
echo '{"sub":"alice"}' | jose jws sign --algorithm RS256 --key-format pem --key rsa.pem > rsa.jws
jose jws verify --algorithm RS256 --key-format pem --key rsa.pem rsa.jws
```

PEM has no room for `kid` or `alg`. `jwk public` adds them while building the
JWKS, so an existing openssl key can still be published with a `kid`:

```shell
openssl ecparam -name prime256v1 -genkey -noout -out ec-openssl.pem
jose jwk public --key-format pem --kid key-1 --alg ES256 --use sig --set ec-openssl.pem > jwks.json
```

The key must then be signed with that `kid` in the header, since the PEM file
cannot remember it:

```shell
echo '{"sub":"alice"}' | jose jws sign --algorithm ES256 --key-format pem --key ec-openssl.pem \
  --header '{"kid":"key-1"}' > ec-openssl.jws
jose jws verify --match-kid --key jwks.json ec-openssl.jws
```

## Pick an algorithm for a key

`jose jwa` lists every name jose accepts:

```shell
jose jwa --signature
jose jwa --key-encryption
jose jwa --content-encryption
```

Which key each algorithm takes. This is also what `--alg` on `jwk generate` and
`jwk public` enforces:

| Algorithm | Key |
|:--|:--|
| ES256 | EC P-256 |
| ES384 | EC P-384 |
| ES512 | EC P-521 |
| EdDSA | OKP Ed25519 |
| RS256, RS384, RS512, PS256, PS384, PS512 | RSA |
| HS256 | oct, 256 bits or more |
| HS384 | oct, 384 bits or more |
| HS512 | oct, 512 bits or more |
| RSA-OAEP, RSA-OAEP-256, RSA1_5 | RSA |
| ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW | EC (any curve) or OKP X25519 |
| A256KW, A256GCMKW | oct, exactly 256 bits |
| dir, PBES2-HS256+A128KW, PBES2-HS384+A192KW, PBES2-HS512+A256KW | oct |

A128KW, A128GCMKW, A192KW, and A192GCMKW need a key of exactly 128 or 192
bits, shorter than the 256-bit minimum `jwk generate` makes, so bring such a
key from elsewhere.

## Script it

jose writes results to standard output and errors to standard error, and exits
with status 0 on success and 1 on any failure. That makes verification a plain
`if`:

```shell
if jose jws verify --algorithm ES256 --key jwks.json token.jwt > /dev/null; then
  echo "valid"
else
  echo "invalid"
fi
```

Every command that takes a message reads standard input when none is named, so
jose sits in a pipe:

```shell
cat token.jwt | jose jws verify --algorithm ES256 --key jwks.json
```

`--output` writes to a file instead of standard output:

```shell
jose jws verify --algorithm ES256 --key jwks.json token.jwt --output claims.json
cat claims.json
```
