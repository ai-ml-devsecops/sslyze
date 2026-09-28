# Use the Smaller SSLyze Image in GitLab CI

The Alpine `flex4lease/sslyze` image built in [part one](blog-alpine-container-optimization.md) was 86.1 MB, compared with 177 MB for the Debian-slim image from the same challenge checkout of SSLyze 6.3.1. The image includes custom `How to fix:` remediation lines when SSLyze finds profile-compliance issues.

This guide runs the image in GitLab CI and records a one-run comparison with `hysnsec/sslyze`. The latter is a lab comparator, not the base image for `flex4lease/sslyze`. Smaller image size alone does not prove fewer vulnerabilities, so use a vulnerability scanner before making a security claim.

## Run a TLS scan job

Use Docker-in-Docker and scan a hostname reachable from the runner:

```yaml
stages:
  - test

tls-scan:
  stage: test
  image: docker:24.0.5
  services:
    - name: docker:24.0.5-dind
  variables:
    DOCKER_TLS_CERTDIR: ""
    DOCKER_HOST: tcp://docker:2375
    TLS_TARGET: example.com
  script:
    - docker pull flex4lease/sslyze:latest
    - docker run --rm flex4lease/sslyze:latest "$TLS_TARGET"
```

When no scan commands are selected, SSLyze uses the Mozilla intermediate profile. When selecting scan commands explicitly, add `--mozilla_config=intermediate` to retain the compliance check. A non-compliant target returns a non-zero exit code, so the command can act as a policy gate. Use `--mozilla_config=disable` only when that check is intentionally out of scope.

## Record pull and scan timings

The benchmark job starts a local Nginx TLS endpoint and scans `localhost:443` with both images. That keeps the target fixed and avoids a public service changing during the run. The fixture uses a self-signed certificate and is deliberately non-compliant, so `|| true` allows timings to be recorded. Remove it from a production policy-gate job.

```yaml
script:
  - |
    { time -p docker pull flex4lease/sslyze:latest; } 2> flex-pull.time
    echo "flex4lease/sslyze:latest,pull,$(awk '/real/ {print $2}' flex-pull.time)" >> benchmark.csv
  - |
    { time -p docker run --rm --network host flex4lease/sslyze:latest localhost:443 || true; } 2> flex-scan.time
    echo "flex4lease/sslyze:latest,scan,$(awk '/real/ {print $2}' flex-scan.time)" >> benchmark.csv
  - cat benchmark.csv
artifacts:
  when: always
  paths:
    - benchmark.csv
```

The complete job also creates the Nginx certificate and configuration, runs the same steps with `hysnsec/sslyze`, and uploads the CSV. It is available in the [pipeline repository](https://gitlab.com/flex4lease/sslyze-pipeline/-/blob/main/.gitlab-ci.yml).

## Results from one pipeline run

Pipeline [#2906554701](https://gitlab.com/flex4lease/sslyze-pipeline/-/pipelines/2906554701) passed with these timings:

| Image | Operation | Time |
|---|---|---:|
| `flex4lease/sslyze:latest` | Pull | 1.46 s |
| `flex4lease/sslyze:latest` | Scan | 1.96 s |
| `hysnsec/sslyze` | Pull | 2.72 s |
| `hysnsec/sslyze` | Scan | 2.24 s |

The [`benchmark.csv` artifact](https://gitlab.com/flex4lease/sslyze-pipeline/-/jobs/16894787916/artifacts/file/benchmark.csv) has the recorded values. These are results from one runner and one execution, not a controlled performance study. Repeat the job under consistent conditions before using it to make a general performance claim.

The image keeps the SSLyze CLI and adds remediation output while reducing the tested image size. Keep the base image current and scan the published image regularly; the build in this example used Alpine 3.20, whose normal support ended April 1, 2026.
