#!/bin/sh

DIR=$1
ADD=$2
MESSAGE=$3

cd $DIR
git add $2
git commit -m "$3"
ret=$?

if [ $ret = 0 ]; then
  git push https://${GITHUB_TOKEN}@github.com/aquasecurity/vuln-list.git main
else
  echo "skip push"
fi
