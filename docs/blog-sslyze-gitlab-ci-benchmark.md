# Use the Smaller SSLyze Image in GitLab CI

The Practical DevSecOps challenge starts from a pipeline that pulls the prebuilt `hysnsec/sslyze` image and asks you to build your own Alpine-based SSLyze image and run it in CI. In [part one](blog-alpine-container-optimization.md), we built `flex4lease/sslyze` from a challenge working copy of the official [nabla-c0d3/sslyze project](https://github.com/nabla-c0d3/sslyze), adding custom `How to fix:` remediation logging and an Alpine Dockerfile. Hysnsec's image was only the lab reference and later CI comparator; it was not used to build ours. This part shows how to run our image in GitLab CI and compare it with that familiar reference.

## Why use the Alpine image?

The published Alpine image is 86.1 MB, compared with 177 MB for the Debian-slim build from the same SSLyze source, a reduction of about 51%. The multi-stage build installs the Python package into a dedicated prefix and copies only that installation into the runtime image. It does not carry the build-stage compiler toolchain into the final image.

A smaller runtime package inventory means fewer inherited OS packages to maintain and can reduce the image's potential attack surface. Image size alone does not prove that an image has fewer vulnerabilities or is safer, so scan images with the same vulnerability database and tools before making that claim. The benchmark below compares pull and scan duration; it is not a CVE scan.

The `latest` tag was pulled back from Docker Hub and verified against the local build. The image ID was `786faf07b33027359ff0854a9f6ae99572afb862fdc3215f41a52b69b38dbbb2`.

The build shown here used `python:3.12-alpine3.20`. Alpine 3.20's normal support period ended on April 1, 2026, according to the [official Alpine release table](https://alpinelinux.org/releases/). For a maintained deployment, update both build stages to a currently supported Python 3.12 Alpine tag, then rebuild and rerun the checks. This is a post-challenge maintenance recommendation: the task requires an Alpine base, not this specific Alpine release. A supported base is a better starting point for receiving OS fixes, but vulnerability scanning is still needed to assess the resulting image.

## Run SSLyze in a pipeline

For a scan job, use a Docker-in-Docker runner and run the image against a hostname reachable from the runner:

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

When no scan commands are explicitly selected, SSLyze runs the Mozilla intermediate compliance check by default, as in the benchmark job below. Use `--mozilla_config=intermediate` to make that choice explicit, or use `--mozilla_config=modern` or `--mozilla_config=old` for another Mozilla profile. If explicitly selecting scan commands, add `--mozilla_config=intermediate` to request the compliance check; use `--mozilla_config=disable` to turn it off. A failed compliance check returns a non-zero exit code, making the command usable as a CI policy gate.

When a server is non-compliant, this image also prints a remediation line for each reported issue, prefixed with `How to fix:`. The custom guidance appears in the GitLab job log from the example run below. It is part of this image's behavior and is not present in the comparison image used by the benchmark.

<!-- Add screenshot 1 at docs/screenshots/custom-how-to-fix.png: capture the How to fix lines in the successful job log. -->

## Benchmark the image

The provided GitLab job starts one local Nginx TLS endpoint and scans that same `localhost:443` target with both `flex4lease/sslyze:latest` and `hysnsec/sslyze`. This keeps the endpoint constant for the timing comparison. The `latest` image's job output includes the custom `How to fix:` guidance for the endpoint's compliance findings; the comparison image reports its scan results without that custom remediation output. The job times image pulls and scans, then uploads `benchmark.csv` as an artifact. Its scan commands use `|| true` because the test endpoint has a self-signed certificate and is deliberately non-compliant. That keeps the benchmark running so it can record timings; remove `|| true` in a production policy-gate job when scan failure should fail the pipeline.

The benchmark job uses Docker-in-Docker as above. These are the image-specific lines in its `.gitlab-ci.yml`; the full job also creates the Nginx test certificate and config, compares with `hysnsec/sslyze`, prints the CSV, and publishes it as an artifact:

```yaml
  script:
    # Benchmark flex4lease image pull
    - |
      { time -p docker pull flex4lease/sslyze:latest; } 2> flex-pull.time
      echo "flex4lease/sslyze:latest,pull,$(awk '/real/ {print $2}' flex-pull.time)" >> benchmark.csv
    # Benchmark flex4lease scan
    - |
      { time -p docker run --rm --network host flex4lease/sslyze:latest localhost:443 || true; } 2> flex-scan.time
      echo "flex4lease/sslyze:latest,scan,$(awk '/real/ {print $2}' flex-scan.time)" >> benchmark.csv
    # Show the measurements in the job log
    - cat benchmark.csv
  artifacts:
    when: always
    paths:
      - benchmark.csv
```

The image name is kept consistent in each pull, run, and CSV label so the artifact identifies exactly what was tested. The complete example is in the [GitLab pipeline repository](https://gitlab.com/flex4lease/sslyze-pipeline/-/blob/main/.gitlab-ci.yml).

## Results

Pipeline [#2906554701](https://gitlab.com/flex4lease/sslyze-pipeline/-/pipelines/2906554701) passed on commit `0fbacb90`. In its single run, the benchmark recorded:

| Image | Operation | Time |
|---|---|---:|
| `flex4lease/sslyze:latest` | Pull | 1.46 s |
| `flex4lease/sslyze:latest` | Scan | 1.96 s |
| `hysnsec/sslyze` | Pull | 2.72 s |
| `hysnsec/sslyze` | Scan | 2.24 s |

The CSV is available as the [`benchmark.csv` job artifact](https://gitlab.com/flex4lease/sslyze-pipeline/-/jobs/16894787916/artifacts/file/benchmark.csv). These timings are a one-run comparison on that runner, not a controlled performance study; repeat the job on the same runner and conditions before drawing broader conclusions.

<!-- Add screenshot 2 at docs/screenshots/gitlab-benchmark-csv.png: capture the benchmark.csv artifact table from job 16894787916. -->

## Takeaway

The Alpine image provides the same SSLyze CLI in a substantially smaller runtime image, and the example demonstrates how to pull it, gate a job on TLS compliance, and retain benchmark results as a GitLab artifact. The smaller footprint is a useful maintenance and attack-surface reduction, but security posture still needs to be confirmed with vulnerability scanning and regular image updates.