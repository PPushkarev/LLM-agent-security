#!/bin/sh
# Uses isolated fixtures instead of placing fake secrets in the real HOME.
set -eu
cd "$(dirname "$0")/.."
go test -count=1 -v ./cmd/guard -run TestAttackAcceptance
go test -count=1 -v ./internal/sandbox
