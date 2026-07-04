#!/usr/bin/env bash
# Combine unit-test coverage with self-hosted E2E coverage into a single
# cover.out. Unit tests report line coverage, but they never exercise the real
# jose binary the way an end user does; the atago E2E specs do. Go 1.20+ lets us
# instrument a built binary (`go build -cover`) and collect its runtime coverage
# via GOCOVERDIR, so we can merge "what the tests cover" with "what a real run
# covers" and get one honest number.
#
# This is intentionally a separate, heavier target: `make test` / `make e2e`
# stay fast and unchanged. Everything lands under .coverage/ (gitignored) except
# the final cover.out / cover.html, which are the same artifacts `make test`
# already produces so octocov and local tooling need no changes.
#
# jwx v4 uses encoding/json/v2, still gated behind GOEXPERIMENT=jsonv2 on Go
# 1.26, so every go invocation here (build AND test) must keep it set — the
# Makefile exports it, and we set it defensively for direct invocations too.
set -euo pipefail

export GOEXPERIMENT="${GOEXPERIMENT:-jsonv2}"

cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
root="$(pwd)"
cov="${root}/.coverage"

rm -rf "${cov}"
mkdir -p "${cov}/unit" "${cov}/e2e" "${cov}/merged"

# 1. Unit-test coverage as raw covdata (GOCOVERDIR form) so it can be merged
#    with the E2E covdata below. -covermode=atomic must match the binary build.
echo ">> unit coverage -> ${cov}/unit"
go test -count=1 -cover -covermode=atomic -coverpkg=./... ./... \
	-args -test.gocoverdir="${cov}/unit"

# 2. Self-hosted E2E via a coverage-instrumented jose. e2e/run.sh builds jose
#    with `go build -cover` (COVER=1), puts it first on PATH, and runs the atago
#    specs; atago passes GOCOVERDIR through to each jose child, which writes its
#    own covdata into ${cov}/e2e.
echo ">> e2e coverage -> ${cov}/e2e"
COVER=1 GOCOVERDIR="${cov}/e2e" ./e2e/run.sh "$@"

# 3. Merge the raw covdata and render the combined text profile + reports.
echo ">> merging unit + e2e covdata -> cover.out"
go tool covdata merge -i="${cov}/unit,${cov}/e2e" -o="${cov}/merged"
go tool covdata textfmt -i="${cov}/merged" -o="${root}/cover.out"

go tool cover -func=cover.out | tail -n 1
go tool cover -html=cover.out -o cover.html
echo ">> wrote cover.out and cover.html (unit + e2e combined)"
