# jose - JSON Object Signing and Encryption CLI tool
The jose command performs set of common operations involving JSON Object Signing and Encryption (otherwise known as JOSE or JWA/JWE/JWK/JWS/JWT). The jose command refers to the jwx command (MIT license, authored by lestrrat) located in [github.com/lestrrat-go/jwx](https://github.com/lestrrat-go/jwx).

The jose command is intended to be a derivative of jwx commands with different functionalities in the future. However, jose is currently in the WIP stage.

## How to install
### Use "go install"
If you does not have the golang development environment installed on your system, please install golang from the golang official website.

$ go install github.com/nao1215/jose@latest

### For Mac user (M1/M2)
$ brew tap nao1215/tap
$ brew install nao1215/tap/jose


### Install from Package or Binary
[The release page](https://github.com/nao1215/jose/releases) contains packages in .deb, .rpm, and .apk formats. gup command uses the go command internally, so the golang installation is required.

## How to use
### jose jwk - generate random JWKs for RSA/EC/oct/OKP key types
**SYNOPSIS**
```
generate a private JWK (JSON Web Key)

Usage:
  jose jwk generate [flags]

Flags:
  -c, --curve string           Elliptic curve type for EC or OKP keys (Ed25519/Ed448/P-256/P-384/P-521/X25519/X448)
  -h, --help                   help for generate
  -o, --output string          Output to file (default "-")
  -O, --output-format string   RSA key output format (json/pem) (default "json")
  -p, --public-key             Display public key
  -s, --size int               RSA key size or oct key size (default 2048)
  -t, --type string            JWK type (RSA/EC/OKP/oct)
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
[WIP] 
### jose jwe encrypt/decrypt
[WIP]
### jose jwa - List supported algorithms
[WIP]

## Contributing
First off, thanks for taking the time to contribute!! Contributions are not only related to development. For example, GitHub Star motivates me to develop!

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