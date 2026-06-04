# Security Policy

## Reporting a Vulnerability

If you discover any security-related issues or vulnerabilities, please contact us at [n.chika156@gmail.com](mailto:n.chika156@gmail.com). We appreciate your responsible disclosure and will work with you to address the issue promptly. Please do not open a public issue for security reports.

## Supported Versions

We recommend using the latest release for the most up-to-date and secure experience. Security updates are provided for the latest stable version.

## Security Notes for JOSE Usage

jose is a thin command line wrapper around the JOSE primitives in [github.com/lestrrat-go/jwx](https://github.com/lestrrat-go/jwx). A few JOSE-specific points are worth keeping in mind when you use it:

- jose never trusts the `alg` field of an incoming JWS to choose how to verify it. You must pass `--algorithm`, or use `--match-kid` to bind verification to an explicit key ID. This avoids the well-known algorithm confusion attacks.
- Generated private keys are written with file mode 0600. Treat key files and any private JWK printed to your terminal as secrets.
- Symmetric (oct) key sizes are specified in bits. Choose a size appropriate to the algorithm you intend to use.

## Security Policy

- Security issues are treated with the highest priority.
- We follow responsible disclosure practices.
- Fixes for security vulnerabilities will be provided in a timely manner.

## Acknowledgments

We would like to thank the security researchers and contributors who responsibly report security issues and work with us to make our project more secure.

Thank you for your help in making our project safe and secure for everyone.
