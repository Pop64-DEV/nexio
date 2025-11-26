#!/usr/bin/env bash
set -euo pipefail

export CGO_ENABLED=0
export GOTOOLCHAIN=${GOTOOLCHAIN:-local}
export GOPROXY=${GOPROXY:-off}
export GOSUMDB=${GOSUMDB:-off}

go build -o nexio -ldflags "-s -w" .
