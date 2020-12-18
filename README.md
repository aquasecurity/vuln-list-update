# vuln-list-update

[![Go Report Card][report-card-img]][report-card]
[![License][license-img]][license]

[report-card-img]: https://goreportcard.com/badge/github.com/aquasecurity/vuln-list-update
[report-card]: https://goreportcard.com/report/github.com/aquasecurity/vuln-list-update
[license-img]: https://img.shields.io/badge/License-Apache%202.0-blue.svg
[license]: https://github.com/aquasecurity/vuln-list-update/blob/main/LICENSE

Collect vulnerability information and save it in parsable format automatically

## Data
https://github.com/aquasecurity/vuln-list/

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
https://travis-ci.org/aquasecurity/vuln-list-update

## Author
Teppei Fukuda (knqyf263)
