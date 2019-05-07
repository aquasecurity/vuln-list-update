# vuln-list-update

[![Build Status](https://travis-ci.org/knqyf263/vuln-list-update.svg?branch=master)](https://travis-ci.org/knqyf263/vuln-list-update)
[![Go Report Card](https://goreportcard.com/badge/github.com/knqyf263/vuln-list-update)](https://goreportcard.com/report/github.com/knqyf263/vuln-list-update)
[![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat)](https://github.com/knqyf263/vuln-list-update/blob/master/LICENSE)

Collect vulnerability information and save it in parsable format automatically

## Data
https://github.com/knqyf263/vuln-list/

## Usage

```
$ vuln-list-update -h
Usage of vuln-list-update:
  -target string
        update target (nvd, alpine, redhat, debian, ubuntu)
  -years string
        update years (only redhat)
```

## Cron status
https://travis-ci.org/knqyf263/vuln-list-update

## Contribute

1. fork a repository: github.com/knqyf263/vuln-list-update to github.com/you/repo
2. get original code: `go get github.com/knqyf263/vuln-list-update`
3. work on original code
4. add remote to your repo: git remote add myfork https://github.com/you/repo.git
5. push your changes: git push myfork
6. create a new Pull Request

- see [GitHub and Go: forking, pull requests, and go-getting](http://blog.campoy.cat/2014/03/github-and-go-forking-pull-requests-and.html)

## Author
Teppei Fukuda (knqyf263)