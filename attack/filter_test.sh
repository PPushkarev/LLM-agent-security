#!/bin/sh
# Local httptest servers use ephemeral ports; no unrelated processes are killed.
set -eu
cd "$(dirname "$0")/.."
go test -count=1 -v ./internal/filter ./internal/proxy
