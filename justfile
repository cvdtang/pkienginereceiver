set shell := ["bash", "-c"]

# Variables
VAULT_ADDR     := env_var_or_default("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_TOKEN    := env_var_or_default("VAULT_TOKEN", "dev-root-token")
TARGET_VERSION := "0.149.0"
BUILDER_CONFIG := "test/builder-config.yaml"
OCB_BIN        := "bin/ocb-" + TARGET_VERSION
DIST_DIR       := "../otelcol-dev"
GO_TEST_TIMEOUT_SHORT := "30s"
GO_TEST_TIMEOUT_LONG  := "3m"

default:
    @just --list

# Quality
fmt:
    terraform fmt -recursive .

lint:
    shellcheck scripts/*.sh
    golangci-lint run
    renovate-config-validator --strict .github/renovate.json

mdatagen:
    go tool mdatagen metadata.yaml

# Tests
test: test-short

test-short:
    go test ./... -short -timeout {{GO_TEST_TIMEOUT_SHORT}}

test-long:
    go test ./... -timeout {{GO_TEST_TIMEOUT_LONG}}

coverage: coverage-short

coverage-short:
    go test -coverprofile=coverage.out ./... -short -timeout {{GO_TEST_TIMEOUT_SHORT}}
    go tool cover -html=coverage.out

coverage-long:
    go test -coverprofile=coverage.out ./... -timeout {{GO_TEST_TIMEOUT_LONG}}
    go tool cover -html=coverage.out

update-golden:
    -go test -v . -update

# Local dev
[working-directory: 'test']
dc-dev:
    docker-compose up
    docker-compose down

[working-directory: 'test/terraform']
tf-apply:
    terraform init -reconfigure -upgrade
    VAULT_ADDR="{{VAULT_ADDR}}" VAULT_TOKEN="{{VAULT_TOKEN}}" terraform apply -auto-approve -parallelism=100

[working-directory: 'test/terraform']
tf-cleanup:
    rm -rf terraform.tfstate terraform.tfstate.backup

# OTEL collector build
update:
    rm -rf {{DIST_DIR}}
    mkdir -p {{DIST_DIR}}
    (cd {{DIST_DIR}} && go mod init otelcol-dev)
    bash -x ./scripts/update.sh {{TARGET_VERSION}}

run-oc:
    {{DIST_DIR}}/otelcol-dev --config ./test/collector-config.yaml

build-oc: get-ocb
    ./{{OCB_BIN}} --config {{BUILDER_CONFIG}}

[private]
get-ocb:
    #!/usr/bin/env bash
    mkdir -p bin
    if [ ! -f {{OCB_BIN}} ]; then
      OS=$(uname -s | tr '[:upper:]' '[:lower:]')
      ARCH=$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')
      URL="https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/cmd%2Fbuilder%2Fv{{TARGET_VERSION}}/ocb_{{TARGET_VERSION}}_${OS}_${ARCH}"
      echo "Downloading OCB from $URL..."
      curl --proto '=https' -fL -o "{{OCB_BIN}}" "$URL"
      chmod +x "{{OCB_BIN}}"
    fi

# CI and release
tidy-check:
    go mod tidy -diff

ci: tidy-check mdatagen lint test-long build-oc

release: update ci
