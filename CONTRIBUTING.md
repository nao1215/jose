# Contributing Guide

First off, thanks for taking the time to contribute. Contributions are not only
about code: reporting a bug, improving the documentation, or starring the
repository all help.

## Development Environment

- Go 1.26 or later (the version is pinned in `go.mod`)
- `make`
- `git`

jose depends on jwx v4, which uses `encoding/json/v2`. On Go 1.26 that package
is gated behind `GOEXPERIMENT=jsonv2`, so the experiment must be set for every
build and test. The `make` targets export it for you; when running `go`
directly, prefix the command, for example `GOEXPERIMENT=jsonv2 go test ./...`.

Optional tools used by the linter, coverage, end-to-end tests, and the demo are
installed with:

```bash
make tools
```

`make tools` installs `shellspec` under `~/.local`, so make sure `~/.local/bin`
is on your `PATH`.

## Common Commands

```bash
make build      # build the jose binary
make test       # unit tests with coverage (writes cover.out / cover.html)
make test-e2e   # shellspec end-to-end tests against the built binary
make test-fuzz  # run each fuzz target for a short time (FUZZ_TIME=20s)
make lint       # golangci-lint
make demo       # regenerate doc/img/demo.gif from the vhs tape (needs vhs)
```

### Tests

- Unit tests live next to the code under `cmd/`. They cover the normal paths,
  error paths, and regressions for every command.
- Property-based tests (`cmd/property_test.go`) assert invariants across all
  supported algorithms: generated keys always parse, public keys carry no
  private material, and sign/verify and encrypt/decrypt always round-trip.
- Metamorphic tests (`cmd/metamorphic_test.go`) assert that different routes to
  the same result agree: file, stdin, and argument inputs parse alike; private
  and derived public keys verify alike; re-encrypting the same plaintext yields
  different ciphertext that decrypts back the same; and repeatedly overwriting
  an output file always leaves a parseable file.
- Fuzz tests (`cmd/fuzz_test.go`) feed arbitrary bytes into the parsing paths
  (`jws parse`, `jws verify`, `jwe decrypt`, `getKeyFile`, header JSON) and
  require that jose never panics.

Run a single fuzz target for longer locally with, for example:

```bash
go test ./cmd/ -run='^$' -fuzz=FuzzJWSParse -fuzztime=2m
```

### End-to-end tests

The `spec/` directory holds shellspec tests that drive the built binary the way
a user does. Run them with `make test-e2e`, or directly with `shellspec --shell
sh` after `make build`.

## Pull Request Expectations

- keep CLI behavior and error messages consistent
- add or update tests for new behavior, including a `spec/` test for CLI changes
- run `make test` and `make test-e2e` before opening a PR
- run `make lint` when changing Go code

## CI

GitHub Actions runs the following workflows, and every gate is reproducible
locally with the `make` targets above:

- `linux_test.yml`, `mac_test.yml`, `windows.yml`: run `go test ./...` (`make test`)
- `e2e_test.yml`: run the shellspec end-to-end tests on Linux and macOS (`make test-e2e`)
- `fuzz.yml`: run the fuzz targets briefly (`make test-fuzz`)
- `reviewdog.yml`: comment on lint and misspell issues in pull requests
- `release.yml`: build and publish release artifacts from git tags with GoReleaser
