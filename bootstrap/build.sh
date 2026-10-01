#!/usr/bin/env bash
# data "external" payload builder: stdout is the JSON result, everything else goes to stderr.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PAYLOAD="$SCRIPT_DIR/../.build/payload"
UV_VERSION=0.11.24

# In the repo, not fetched: a digest served by the artifact's own host proves nothing.
UV_SHA256_x86_64=5ce1ad074a78f96c5c8122088bb85a12eb282195bc1453151a48762e4fc31fed
UV_SHA256_aarch64=e22c66d36a0098b17cff80a8647e0b8c58202af899d4e9eb820fc7ad126435a1
UV_SHA256_darwin_arm64=7578c6087c5cd76981732b1f5d126248101faebdf81016ba780a65ce03653cdf

# Before any subprocess can inherit this stdin.
QUERY=$(cat)

{
  if [ "$(uv --version 2>/dev/null | awk '{print $2}' || true)" != "$UV_VERSION" ]; then
    case "$(uname -s)/$(uname -m)" in
      Linux/x86_64) uv_target=x86_64-unknown-linux-gnu; uv_sha=$UV_SHA256_x86_64 ;;
      Linux/aarch64) uv_target=aarch64-unknown-linux-gnu; uv_sha=$UV_SHA256_aarch64 ;;
      Darwin/arm64) uv_target=aarch64-apple-darwin; uv_sha=$UV_SHA256_darwin_arm64 ;;
      *)
        echo "uv $UV_VERSION is unavailable and no digest is pinned for $(uname -s)/$(uname -m)" >&2
        exit 1
        ;;
    esac

    uv_dir=$(mktemp -d)
    trap 'rm -rf "$uv_dir"' EXIT
    curl -fsSL -o "$uv_dir/uv.tar.gz" \
      "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-${uv_target}.tar.gz"
    echo "${uv_sha}  ${uv_dir}/uv.tar.gz" | sha256sum -c - >/dev/null
    tar -xzf "$uv_dir/uv.tar.gz" -C "$uv_dir" --strip-components=1
    export PATH="$uv_dir:$PATH"
  fi

  rm -rf "$PAYLOAD"
  mkdir -p "$PAYLOAD"

  uv pip install \
    --target "$PAYLOAD" \
    --python-version 3.14 \
    --python-platform aarch64-manylinux2014 \
    --no-deps \
    --no-compile \
    --require-hashes \
    -r "$SCRIPT_DIR/requirements.txt"

  cp "$SCRIPT_DIR/handler.py" "$PAYLOAD/"

  # One read of stdin writes both query-carried files; sort_keys keeps the archive bytes stable
  # across plans, so an unchanged config never shows up as a code change.
  printf '%s' "$QUERY" | python3 -c '
import json, sys

query = json.load(sys.stdin)
payload = sys.argv[1]

with open(f"{payload}/rds-global-bundle.pem", "w") as pem:
    pem.write(query["ca_bundle"])

with open(f"{payload}/bootstrap-config.json", "w") as config:
    json.dump(json.loads(query["bootstrap_config"]), config, sort_keys=True)
' "$PAYLOAD"
  grep -q -- "-----BEGIN CERTIFICATE-----" "$PAYLOAD/rds-global-bundle.pem"

  find "$PAYLOAD" -exec touch -h -t 200001010000 {} +
} >&2

printf '{"payload_dir":"%s"}\n' "$PAYLOAD"
