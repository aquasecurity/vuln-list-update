#!/bin/bash -eu

TARGET=$1

if [ -z "$TARGET" ]; then
  echo "target required"
  exit 1
fi

./vuln-list-update -vuln-list-dir "$VULN_LIST_DIR" -target "$TARGET" || {
  echo "[Err] Revert changes" >&2
  cd "$VULN_LIST_DIR" && git reset --hard HEAD
  exit 1
}
