BINARY_NAME := varax
BUILD_DIR := bin
MODULE := github.com/varax/operator

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

LDFLAGS := -ldflags "\
	-X $(MODULE)/cmd/varax.Version=$(VERSION) \
	-X $(MODULE)/cmd/varax.Commit=$(COMMIT) \
	-X $(MODULE)/cmd/varax.BuildTime=$(BUILD_TIME) \
	-s -w"

CONTROLLER_GEN ?= $(shell which controller-gen 2>/dev/null)

.PHONY: all build test generate manifests fmt vet clean docker-build examples

all: fmt vet build

build:
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/varax/

test:
	go test ./... -coverprofile=coverage.out -race
	@go tool cover -func=coverage.out | tail -1

generate:
	$(CONTROLLER_GEN) object paths="./api/..."

manifests:
	$(CONTROLLER_GEN) crd rbac:roleName=varax-manager-role paths="./..." output:crd:artifacts:config=config/crd/bases

fmt:
	go fmt ./...

vet:
	go vet ./...

clean:
	rm -rf $(BUILD_DIR) coverage.out coverage.html

docker-build:
	docker build -t varax:$(VERSION) .

coverage-html: test
	go tool cover -html=coverage.out -o coverage.html

lint:
	golangci-lint run ./...

examples:
	go run examples/generate.go
