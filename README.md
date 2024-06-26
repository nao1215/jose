![Coverage](https://raw.githubusercontent.com/nao1215/octocovs-central-repo/main/badges/nao1215/jose/coverage.svg)
![Test Execution Time](https://raw.githubusercontent.com/nao1215/octocovs-central-repo/main/badges/nao1215/jose/time.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/nao1215/jose)](https://goreportcard.com/report/github.com/nao1215/jose)
[![reviewdog](https://github.com/nao1215/jose/actions/workflows/reviewdog.yml/badge.svg)](https://github.com/nao1215/jose/actions/workflows/reviewdog.yml)
[![LinuxUnitTest](https://github.com/nao1215/jose/actions/workflows/linux_test.yml/badge.svg)](https://github.com/nao1215/jose/actions/workflows/linux_test.yml)
[![MacUnitTest](https://github.com/nao1215/jose/actions/workflows/mac_test.yml/badge.svg)](https://github.com/nao1215/jose/actions/workflows/mac_test.yml)
[![WindowsUnitTest](https://github.com/nao1215/jose/actions/workflows/windows.yml/badge.svg)](https://github.com/nao1215/jose/actions/workflows/windows.yml)
# jose - JSON Object Signing and Encryption CLI tool
The jose command performs set of common operations involving JSON Object Signing and Encryption (otherwise known as JOSE or JWA/JWE/JWK/JWS/JWT). The jose command refers to the jwx command (MIT license, authored by lestrrat) located in [github.com/lestrrat-go/jwx](https://github.com/lestrrat-go/jwx).

The jose command is intended to be a derivative of jwx commands with different functionalities in the future. However, jose is currently in the WIP stage.

## How to install
### Use "go install"
If you does not have the golang development environment installed on your system, please install golang from the golang official website.
```shell
go install github.com/nao1215/jose@latest
```

### Use homebrew
```shell
brew install nao1215/tap/jose
```

### Install from Package or Binary
[The release page](https://github.com/nao1215/jose/releases) contains packages in .deb, .rpm, and .apk formats. gup command uses the go command internally, so the golang installation is required.

## Supported OS (tested OS)
- Linux (main target)
- Mac
- Windows

## How to use
### jose jwk - generate random JWKs for RSA/EC/oct/OKP key types
**SYNOPSIS**
```
Usage:
  jose jwk generate [flags]

Aliases:
  generate, gen

Flags:
  -c, --curve string           elliptic curve type for EC or OKP keys (Ed25519/Ed448/P-256/P-384/P-521/X25519/X448)
  -h, --help                   help for generate
  -o, --output string          output to file (default "-")
  -O, --output-format string   rsa key output format (json/pem) (default "json")
  -p, --public-key             display public key
  -s, --size int               rsa key size or oct key size (default 2048)
  -t, --type string            jwk type (RSA/EC/OKP/oct)
```

**Usage**
```
$ jose jwk generate --type RSA --curve P-521 --size 2048 --output-format json 
{
    "d": "fPjWsCgisIxUNM5Sn2kWMtIUmkUgJzo2opKQUfoawhw4ku34tApW8OFbM-uufRpnpgiUpYxXFkMZvFd5A6k0XFWgsmmEvuZajbCJ1DDx8Zk3LlsvkMUY26qbqfl6r86UPIBecXeNOvF6c4BPKXxBqxmNy0BhoKgb962DGqqQfOkTNPLiYYtZkbbGPGIfRT6nHOC-cttDhiZcMsVT8M6rDLI16BIVbSNlAC9QyhA15U7rS4ZDGQwUCbwAjSahuSQ-6j7znlVpMgg5YP89ycfFK53s2OA2vsCac0K-uQAU8R2o3e8hxF72ajqCH27ozeGSpBtA1e8kUzogYrOHmIHpOQ",
    "dp": "tVgMV9qAbaiYS8bmNAyzpx3FYGMMiuUKSkhO1cbgSdqATuaf37mCIgnkb0cQJ5NrQC0wcrD9p8_lupQ-WBucdYMijCCjYVUw6LwcVcViVZ50_inSocZPbsot6pv2KwuUA88YdMWzDFBnalhaPAoouMwmb78NcDqdtZrK861K_fc",
    "dq": "pNqAeI3_jG70A3-pC_fhGGTYPXsBHpX6PfcukLvvH2Nq5FOLCuYqqAB5BGS098ix_6HbQaXNI62nN30--KbaW8rHi0hCpWwAalcmZTMzYg-FTWM1JpR0faTP5p6cjz0ZhEtgmSOMBqn-G2QR-AdB12lcfbE72IEXoTp39A-pDxU",
    "e": "AQAB",
    "kty": "RSA",
    "n": "rtK8n9ZPwCu9qzfCvjaCpwZ43NtwtFZCe9cId54EXJq-XOWtGEBG94bB0_ZJXmxzK1mdI7FyoRcp1mw8Dz8sczi1l4tdL6ONB67zLdsPx1GrT5n1Qb7Rq_zqGLdSdXU8-MjuCak1NY9jFzYYaeVteZrs0asqQvhFdjrHauAtJ5foNOF9ZIO2GdX-kHfIQLx065fGXCcK2WHQmdTsuKE_kO83mihTzo2dEzXDcpFyX_vjrNwrpNfXLMeA2wPwMhk8coub4uIOzfmfkt3Fhxyd0gA7-NeGdxihcsefm2eONVOgoVuNzdHfxpWhegmcUbUvLbBsQbzeUYgQq9ywdOIjiw",
    "p": "1Ohy8fv01DsBIBN0P3doFu_dIyUn-gbpfjK31EGup8NA4Gt-Bc_0mygZLH8a-55K6ETeGDGRai38t_KmSLLOE4_4qKwthXi2Jl8z8jHQh4gdAVjzaMq16rNPYlt1llqNdaubp-I1PEEMPmNYs4m4GDNAJ4CRNejixhyzyTTgRk8",
    "q": "0jT5CX2m7MWAl6y-OelsFJxDDbp4dFkKokC5Py8z4cn4I5NGcjdxxy8rKcr1_GmAwt6Wh0E_dU6_GbVZeu5eLkwscHdezwG6QAWApEu7RVAVbA_P1ZI_ZYVZgfzHPh1C3Vzctp46HhB9izrs0b03YBJE64rWpxyYfCID2QxF_AU",
    "qi": "S6Tmpnhw3UOOYWVgZthFinRhIzmUeQj78ZJYXBfcMiyV1PdVPejYM3iAIu-yDpVx8rvaC1A-1EAmVZmrCNBy6-qRMhtqafJc1CLbRnDH2Zz-dSHgKEqsgFjS_P6wsB8dS8HjHgYeADY-zxhb-5YR4R5YsbKb02h3Y4uSDbzcEF0"
}
```
```
$ jose jwk generate --type EC --curve P-384 --size 4096 --output-format pem
-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDC325MGKdl+C9a60nW7
LAADPndGbRmSKJVEJxVe5CMYZi6Z4tXEXTg+I91S4OQdNoChZANiAATstOXgqs+H
U3FtLxLeLsA2Juq6P00DJJYedAyo4jnnK8HrIe8p3xgr2o8QkEphPt1aM7sFTMdh
KcI48LscuQT0Q0ROWdWLnpPJe/Zags78zSkQT053rLCn6aceO5cdY6o=
-----END PRIVATE KEY-----
```

### jose jws - Parses the given JWS message, and prints out the content in a human-redable format
### jose jws parse
Parses the given JWS message, and prints out the content in a human-redable format.
**parse SYNOPSIS**
```
Parse JWS and display payload in the JWS message.
Use "-" as FILE to read from STDIN.

Usage:
  jose jws parse [flags]

Flags:
  -a, --all    print all information (payload, header, signature)
  -h, --help   help for parse
```

**parse usage**
```
※ JWS to be parsed
$ cat cmd/testdata/jws/sample.jws 
eyJhbGciOiJFUzI1NiJ9.SGVsbG8sIFdvcmxkIQ.YP7wVtRe3TxLFkeJ2ei83f67ZT5ajMUSu2GZhTYFeFR5R2yu1vv1emH3ikhBk09czvFFaA41zDBT-KsB1EqphA

※ Read JWS from file and print all information
$ jose jws parse --all cmd/testdata/jws/sample.jws
Payload: Hello, World!
JWS: {
    "payload": "SGVsbG8sIFdvcmxkIQ",
    "protected": "eyJhbGciOiJFUzI1NiJ9",
    "signature": "YP7wVtRe3TxLFkeJ2ei83f67ZT5ajMUSu2GZhTYFeFR5R2yu1vv1emH3ikhBk09czvFFaA41zDBT-KsB1EqphA"
}
Signature 0: {
    "alg": "ES256"
}
 
※ Read JWS from argument and print only payload
$ jose jws parse eyJhbGciOiJFUzI1NiJ9.SGVsbG8sIFdvcmxkIQ.
Hello, World!
```

### jose jws verify
Parses a JWS message in FILE, and verifies using the specified method.Use "-" as FILE to read from STDIN.

By default the user is responsible for providing the algorithm to
use to verify the signature. This is because we can not safely rely
on the "alg" field of the JWS message to deduce which key to use.
See https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
 
The alternative is to match a key based on explicitly specified key ID ("kid"). In this case the following conditions must be met for a successful verification:

  1. JWS message must list the key ID that it expects
  2. At least one of the provided JWK must contain the same key ID
  3. The same key must also contain the "alg" field 

Therefore, the following key may be able to successfully verify a JWS message using "--match-kid":

  { "typ": "oct", "alg": "H256", "kid": "mykey", .... }

### jose jws sign
Creates a signed JWS message in compact format from a key and payload.

**sign SYNOPSIS**
```
Usage:
  jose jws sign [flags]

Flags:
  -a, --algorithm string    algorithm to use in single key mode (default "none")
  -H, --header string       header object to inject into JWS message protected header
  -h, --help                help for sign
  -k, --key string          file name that contains the key to use. single JWK or JWK set
  -F, --key-format string   format of the store key (json/pem) (default "json")
  -o, --output string       output to file (default "-")
```

**sign usage**
```
$ cat cmd/testdata/jwe/payload.txt
Hello, World!

$ cat cmd/testdata/jwe/ec.jwk
{
    "crv": "P-256",
    "d": "vdX2dzkoF1wxYHYWDuTvSs0NHRcKSHz1ThgkhBerlpE",
    "kty": "EC",
    "x": "XfXquPuOb7tP3n9J45U22yvHGyR4GUKsU475LOExrfg",
    "y": "3bYyiO-bTS0RYnKaKA8ugmBU6VMx3QuciqEKL9Vwrd0"
}

$ jose jws sign --key cmd/testdata/jwe/ec.jwk --algorithm ES256 cmd/testdata/jwe/payload.txt
eyJhbGciOiJFUzI1NiJ9.SGVsbG8sIFdvcmxkIQ.HzKoOIfguqaZy2SYB6mB92ztntoTMqu-7eIykGuPa4GukC0MIPhNnHURuJIxpAKtDizAt6p_YwMnvQowYntCLQ
```

**verify SYNOPSIS**
```
Usage:
  jose jws verify [flags]

Flags:
  -a, --algorithm string    algorithm to use in single key mode (default "none")
  -h, --help                help for verify
  -k, --key string          file name that contains the key to use. single JWK or JWK set
  -F, --key-format string   format of the store key (json/pem) (default "json")
  -m, --match-kid           instead of using alg, attempt to verify only if the key ID (kid) matches
  -o, --output string       output to file (default "-")
```

### jose jwe encrypt/decrypt
**encrypt SYNOPSIS**
```
Usage:
  jose jwe encrypt [flags]

Aliases:
  encrypt, enc

Flags:
  -z, --compress                  Enable compression
  -c, --content-encryption NAME   Content encryption algorithm name NAME (A128CBC-HS256/A128GCM/A192CBC-HS384/A192GCM/A256CBC-HS512/A256GCM)
  -h, --help                      help for encrypt
  -k, --key string                JWK to encrypt with
  -K, --key-encryption NAME       Key encryption algorithm name NAME (e.g. RSA-OAEP, ECDH-ES, etc)
  -F, --key-format string         JWK format: json or pem (default "json")
  -o, --output string             output to file (default "-")
```

**encrypt usage**
```
※ Message to be Encrypt
$ cat cmd/testdata/jwe/payload.txt
Hello, World!

※ Generate JWK to be used for Encrypt
$ jose jwk generate --curve P-256 --type EC > cmd/testdata/jwe/ec.jwk

$ jose jwe encrypt --key cmd/testdata/jwe/ec.jwk --key-encryption ECDH-ES --content-encryption A256CBC-HS512 cmd/testdata/jwe/payload.txt
eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkNCQy1IUzUxMiIsImVwayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImRMUFp6dUNMb29xeGJJNUI3dzc0RmNicUdwLXlMb2dUX0ZRVkMtQTZQNjAiLCJ5IjoiRUJTTmpFb3hKdUV2ckVFek5qTjlzOFRDUEd5QnBjcG1mV0RkeEtxcnZOWSJ9fQ..2Qw30wTTD5OS-bmZTt6kkg.xJ5sPix2QUJKjh_gl0SReA.Zm7AkepHGYgQ24Tf67-47rP0UWmQKOgZKzt2X1RTMFc
```

**decrypt SYNOPSIS**
```
Usage:
  jose jwe decrypt [flags]

Aliases:
  decrypt, dec

Flags:
  -h, --help                  help for decrypt
  -k, --key string            JWK to decrypt with
  -K, --key-encryption NAME   Key encryption algorithm name NAME (e.g. RSA-OAEP, ECDH-ES, etc)
  -F, --key-format string     JWK format: json or pem (default "json")
  -o, --output string         output to file (default "-"
```

**decrypt usage**
```
※ Encrypt the contents of payload.txt and save it in message.jwe
$ jose jwe encrypt --key cmd/testdata/jwe/ec.jwk --key-encryption ECDH-ES --content-encryption A256CBC-HS512 cmd/testdata/jwe/payload.txt > cmd/testdata/jwe/message.jwe

$ cat cmd/testdata/jwe/message.jwe 
eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkNCQy1IUzUxMiIsImVwayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IjRpUVVDakJZbVJ2ZHY0TDVQaEVuSG5LVUpLdzRzUzZfN0hYa1JnQ3FCVWsiLCJ5IjoicEtkMGxjZXBuVy1uYThLWV9BM2RocHg1aG84cWdQOFRGY21obFBHNk1ydyJ9fQ..zdhh12XQ2imtVWXCKgufvg.5LPIRDY1Y351zdHxf0AG8Q.COXEOkONS9fiLluvmya_kAL5sm3G9_FtsoHtEfa5bxM

$ jose jwe decrypt --key cmd/testdata/jwe/ec.jwk cmd/testdata/jwe/message.jwe 
Hello, World!
```

### jose jwa - List supported algorithms
**SYNOPSIS**
```
Usage:
  jose jwa [flags]

Flags:
  -c, --content-encryption   print content encryption algorithms
  -e, --elliptic-curve       print elliptic curve types
  -h, --help                 help for jwa
  -K, --key-encryption       print key encryption algorithms
  -k, --key-type             print JWK key types
  -s, --signature            print signature algorithms
```

**Usage**
```
$ jose jwa --key-type
EC
OKP
RSA
oct
```

## Contributing
First off, thanks for taking the time to contribute!! Contributions are not only related to development. For example, GitHub Star motivates me to develop!

[![Star History Chart](https://api.star-history.com/svg?repos=nao1215/jose&type=Date)](https://star-history.com/#nao1215/jose&Date)


## Contact
If you would like to send comments such as "find a bug" or "request for additional features" to the developer, please use one of the following contacts.

- [GitHub Issue](https://github.com/nao1215/jose/issues)

You can use the bug-report subcommand to send a bug report.
```
$ jose bug-report
※ Open GitHub issue page by your default browser
```

## LICENSE
The jose project is licensed under [MIT LICENSE](./LICENSE).
