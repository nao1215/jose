.PHONY: build test coverage e2e test-fuzz lint clean demo demo-pipe tools help

# jwx v4 uses encoding/json/v2, which is still gated behind GOEXPERIMENT=jsonv2
# on Go 1.26. Export it for every go invocation in this Makefile.
export GOEXPERIMENT := jsonv2

APP         = jose
VERSION     = $(shell git describe --tags --abbrev=0 2>/dev/null || echo dev)
GO          = go
GO_BUILD    = $(GO) build
GO_TEST     = $(GO) test
GO_TOOL     = $(GO) tool
GO_INSTALL  = $(GO) install
GOOS        = ""
GOARCH      = ""
GO_PKGROOT  = ./...
GO_LDFLAGS  = -ldflags '-X github.com/nao1215/jose/cmd.Version=$(VERSION)'

build: ## Build binary
	env GO111MODULE=on GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO_BUILD) $(GO_LDFLAGS) -o $(APP) main.go

clean: ## Clean project
	-rm -rf $(APP) cover.out cover.html .coverage

test: ## Run unit tests with coverage (writes cover.out / cover.html)
	env GOOS=$(GOOS) $(GO_TEST) -cover $(GO_PKGROOT) -coverprofile=cover.out
	$(GO_TOOL) cover -html=cover.out -o cover.html

coverage: ## Combine unit + self-hosted E2E coverage into cover.out / cover.html (builds a `go build -cover` jose; scratch under .coverage/, needs atago on PATH)
	bash ./scripts/coverage.sh

e2e: ## Run atago end-to-end tests against the freshly built binary
	./e2e/run.sh

FUZZ_TIME ?= 20s
test-fuzz: ## Run each fuzz target for FUZZ_TIME (default 20s)
	@for fz in FuzzJWSParse FuzzJWSVerify FuzzJWEDecrypt FuzzGetKeyFile FuzzSignOptionsHeader; do \
		echo "== $$fz =="; \
		$(GO_TEST) ./cmd/ -run="^$$fz$$" -fuzz="^$$fz$$" -fuzztime=$(FUZZ_TIME) || exit 1; \
	done

lint: ## Run golangci-lint
	golangci-lint run --config .golangci.yml

DEMO_BIN = /tmp/$(APP)
DEMO_DIR = /tmp/$(APP)-demo

demo: build ## Regenerate the README gif from doc/img/demo.tape (needs vhs)
	@command -v vhs >/dev/null || { echo 'vhs is required: go install github.com/charmbracelet/vhs@latest'; exit 1; }
	cp $(APP) $(DEMO_BIN)
	rm -rf $(DEMO_DIR) && mkdir -p $(DEMO_DIR)
	printf '{"sub":"alice"}' > $(DEMO_DIR)/payload.json
	vhs doc/img/demo.tape && mv demo.gif doc/img/demo.gif
	rm -rf $(DEMO_DIR) $(DEMO_BIN)
	@echo 'Wrote doc/img/demo.gif'

DEMO_PIPE_DIR = /tmp/$(APP)-pipe-demo

demo-pipe: build ## Regenerate the pipe gif from doc/img/pipe.tape (needs vhs)
	@command -v vhs >/dev/null || { echo 'vhs is required: go install github.com/charmbracelet/vhs@latest'; exit 1; }
	cp $(APP) $(DEMO_BIN)
	rm -rf $(DEMO_PIPE_DIR) && mkdir -p $(DEMO_PIPE_DIR)
	printf '{"sub":"alice"}' > $(DEMO_PIPE_DIR)/payload.json
	vhs doc/img/pipe.tape && mv pipe.gif doc/img/pipe.gif
	rm -rf $(DEMO_PIPE_DIR) $(DEMO_BIN)
	@echo 'Wrote doc/img/pipe.gif'

tools: ## Install developer tools (linter, coverage, atago for e2e)
	$(GO_INSTALL) github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	$(GO_INSTALL) github.com/k1LoW/octocov@latest
	$(GO_INSTALL) github.com/charmbracelet/vhs@latest
	$(GO_INSTALL) github.com/nao1215/atago@latest

.DEFAULT_GOAL := help
help:
	@grep -E '^[0-9a-zA-Z_-]+[[:blank:]]*:.*?## .*$$' $(MAKEFILE_LIST) | sort \
	| awk 'BEGIN {FS = ":.*?## "}; {printf "\033[1;32m%-15s\033[0m %s\n", $$1, $$2}'
