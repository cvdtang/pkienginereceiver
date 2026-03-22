#!/bin/bash

set -eo pipefail

if [ -z "$1" ]; then
    echo "Error: Missing TARGET_VERSION argument."
    echo "Usage: $0 <TARGET_VERSION>"
    echo "Example: $0 0.145.0"
    exit 1
fi

TARGET_VERSION="$1"
echo "Targeting OpenTelemetry Collector version: $TARGET_VERSION"

# Use this package as a sample to get the current version
LOOKUP_PACKAGE="go.opentelemetry.io/collector/scraper/scraperhelper"

CURRENT_VERSION=$(go list -m -f '{{.Version}}' ${LOOKUP_PACKAGE})

# Update Go Modules
OTEL_PKGS=$(go list -m -f '{{if not .Indirect}}{{.Path}} {{.Version}}{{end}}' all \
    | grep -E '^(go\.opentelemetry\.io/collector|github\.com/open-telemetry/opentelemetry-collector-contrib)' \
    | grep "$CURRENT_VERSION")

while read -r PKG_PATH CURRENT_VERSION; do
    if [ "$CURRENT_VERSION" == "v$TARGET_VERSION" ]; then
        continue
    fi

    echo "Modified: $PKG_PATH $CURRENT_VERSION -> $TARGET_VERSION"
    go get "$PKG_PATH"@v"$TARGET_VERSION"
done <<< "$OTEL_PKGS"

go mod tidy

# Update Builder Config YAML
BUILDER_CONFIG="./test/builder-config.yaml"
awk -v new_ver="v${TARGET_VERSION}" '
/go\.opentelemetry\.io\/collector\/(exporter|processor|receiver)\// ||
/github\.com\/open-telemetry\/opentelemetry-collector-contrib\/(exporter|processor|receiver)\// {
    $NF = new_ver
}
1' "$BUILDER_CONFIG" > "${BUILDER_CONFIG}.tmp" && mv "${BUILDER_CONFIG}.tmp" "$BUILDER_CONFIG"

# Update provider modules to their latest available versions.
PROVIDER_MODULES=$(awk '
/go\.opentelemetry\.io\/collector\/confmap\/provider\// {
    for (i = 1; i <= NF; i++) {
        if ($i ~ /^go\.opentelemetry\.io\/collector\/confmap\/provider\//) {
            print $i
        }
    }
}
' "$BUILDER_CONFIG" | sort -u)

if [ -n "$PROVIDER_MODULES" ]; then
    PROVIDER_VERSION_FILE=$(mktemp)

    while read -r PROVIDER_MODULE; do
        [ -z "$PROVIDER_MODULE" ] && continue

        LATEST_PROVIDER_VERSION=$(go list -m -f '{{.Version}}' "${PROVIDER_MODULE}@latest")
        echo "Modified: ${PROVIDER_MODULE} -> ${LATEST_PROVIDER_VERSION}"
        printf '%s %s\n' "$PROVIDER_MODULE" "$LATEST_PROVIDER_VERSION" >> "$PROVIDER_VERSION_FILE"
    done <<< "$PROVIDER_MODULES"

    awk '
NR == FNR {
    latest[$1] = $2
    next
}
/go\.opentelemetry\.io\/collector\/confmap\/provider\// {
    for (i = 1; i <= NF; i++) {
        if ($i in latest) {
            $NF = latest[$i]
            break
        }
    }
}
1
' "$PROVIDER_VERSION_FILE" "$BUILDER_CONFIG" > "${BUILDER_CONFIG}.tmp" && mv "${BUILDER_CONFIG}.tmp" "$BUILDER_CONFIG"

    rm -f "$PROVIDER_VERSION_FILE"
fi

go get -u go.opentelemetry.io/collector/cmd/mdatagen@v"${TARGET_VERSION}"
go mod tidy
