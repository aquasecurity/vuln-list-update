#!/bin/bash -eu

TARGET=$1
COMMIT_MSG=$2

if [ -z "$TARGET" ]; then
  echo "target required"
  exit 1
fi

if [ -z "$COMMIT_MSG" ]; then
  echo "commit message required"
  exit 1
fi

./vuln-list-update -vuln-list-dir "$VULN_LIST_DIR" -target "$TARGET"

cd "$VULN_LIST_DIR" || exit 1

if [[ -n $(git status --porcelain) ]]; then
  git add .
  git commit -m "${COMMIT_MSG}"
  git push
fi