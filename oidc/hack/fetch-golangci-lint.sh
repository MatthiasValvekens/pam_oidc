#!/usr/bin/env bash
set -euo pipefail

golangci_lint_version="2.11.4"
golangci_lint_sha256="unknown" # set in platform block below

goarch=amd64 # it's 2020
goos="unknown"

if [[ "$OSTYPE" == "linux-gnu" ]]; then
  goos="linux"
  golangci_lint_sha256="200c5b7503f67b59a6743ccf32133026c174e272b930ee79aa2aa6f37aca7ef1"
elif [[ "$OSTYPE" == "darwin"* ]]; then
  goos="darwin"
  golangci_lint_sha256="c900d4048db75d1edfd550fd11cf6a9b3008e7caa8e119fcddbc700412d63e60"
fi

srcdir="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." >/dev/null 2>&1 && pwd )"

if [ -f "$srcdir/bin/golangci-lint-${golangci_lint_version}" ]; then
    echo "--> Already downloaded"
    exit 0
fi

workdir=$(mktemp -d)

function cleanup {
  rm -rf "$workdir"
}
trap cleanup EXIT

echo "--> Downloading"
curl -sLo "$workdir/download.tgz" "https://github.com/golangci/golangci-lint/releases/download/v${golangci_lint_version}/golangci-lint-${golangci_lint_version}-${goos}-${goarch}.tar.gz"

echo "--> Unpacking"
cd "$workdir"
tar -zxf "$workdir/download.tgz"
mv golangci-lint*/golangci-lint .

echo "--> Verifying"
echo "$golangci_lint_sha256 *golangci-lint" | shasum -a 256 -c -

mkdir -p "$srcdir/bin"
mv golangci-lint "$srcdir/bin/golangci-lint-${golangci_lint_version}"
echo "--> Fetched bin/golangci-lint-${golangci_lint_version}"
