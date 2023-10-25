#!/bin/bash -eu

TARGET=$1

if [ -z "$TARGET" ]; then
  echo "target required"
  exit 1
fi

./vuln-list-update -vuln-list-dir "$VULN_LIST_DIR" -target "$TARGET"

cd "$VULN_LIST_DIR" || exit 1

if [[ -n $(git status --porcelain) ]]; then
  # List changed files
  CHANGED_FILES=$(git ls-files . --exclude-standard --others | grep "CVE")
  REPO="$REPOSITORY_OWNER/$VULN_LIST_DIR"
  BASE_BRANCH="main"
  # Loop through changed files and create PRs
  for FILE in $CHANGED_FILES; do

    BRANCH_NAME=$(echo "$FILE" | tr / -)
    PR_TITLE="Update $FILE"
    PR_BODY="This PR updates $FILE"

    # Check if a PR with the same branch name already exists
    OPEN_PR_COUNT=$(gh pr list --state open --base $BASE_BRANCH --repo "$REPO"  --limit 50| grep "$FILE" | wc -l)

    if [ "$OPEN_PR_COUNT" != 0 ]; then
      echo "PR for $FILE already exists, skipping."
      continue
    fi

    # Create a new branch and push it
    git checkout -b "$BRANCH_NAME"
    echo "$FILE"
    git add "$FILE"
    git commit -m "Update $FILE"

    git push origin "$BRANCH_NAME" --force
    # Create a new pull request using gh
    gh pr create --base "$BASE_BRANCH" --head "$BRANCH_NAME" --title "$PR_TITLE" --body "$PR_BODY" --repo "$REPO"

    git checkout $BASE_BRANCH

    sleep 30
  done
fi
