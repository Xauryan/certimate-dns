#!/usr/bin/env bash
set -euo pipefail

kind=$1
tag=$2
platform=$3
binary=$4
output=$5

case "$kind" in
  server)
    name=certimate
    readme=README.md
    ;;
  agent)
    name=certimate-ddns-agent
    readme=cmd/ddns-agent-native/INSTALL.md
    ;;
  *)
    printf 'Unknown release package type: %s\n' "$kind" >&2
    exit 1
    ;;
esac

entrypoint=$name
if [[ "$platform" == windows_* ]]; then
  entrypoint+=.exe
fi

staging=$(mktemp -d)
trap 'rm -rf -- "$staging"' EXIT
install -m 0755 "$binary" "$staging/$entrypoint"
install -m 0644 LICENSE "$staging/LICENSE"
install -m 0644 "$readme" "$staging/README.md"
if [[ "$kind" == server ]]; then
  install -m 0644 CHANGELOG.md "$staging/CHANGELOG.md"
elif [[ "$platform" == linux_* ]]; then
  install -m 0644 deploy/systemd/certimate-ddns-agent-native.{service,timer} "$staging/"
fi

mkdir -p "$output"
archive="$output/${name}_${tag}_${platform}.zip"
test ! -e "$archive"
zip -j -X -q "$archive" "$staging"/*
unzip -tq "$archive"
