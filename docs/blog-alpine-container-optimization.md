# Build a Smaller Alpine SSLyze Container

The Practical DevSecOps challenge begins with the prebuilt `hysnsec/sslyze` image and asks for an Alpine-based alternative. We built `flex4lease/sslyze` from a challenge working copy of the official [SSLyze project](https://github.com/nabla-c0d3/sslyze), adding custom `How to fix:` remediation logging and an Alpine Dockerfile. Hysnsec's image was a lab reference and later CI comparator. It was not the base image or source for our build.

The resulting Alpine image was 86.1 MB, compared with 177 MB for the Debian-slim Dockerfile built from the same checkout. This is a size comparison, not a vulnerability assessment.

## Choose Alpine with the Python dependency tradeoff in mind

Alpine uses musl rather than glibc. Python packages with C extensions need compatible `musllinux` wheels or a source build with a compiler toolchain. That can make Debian-slim the safer default for tools with crypto dependencies, including SSLyze's `nassl` binding.

For this build, on Python 3.12 and `linux-x86_64`, `nassl` and `cryptography` installed from musllinux wheels. No compiler or Alpine build dependencies were needed. Check wheel availability again before adopting Alpine on another architecture or Python version.

Use a currently supported Alpine Python tag for ongoing deployment. This example used `python:3.12-alpine3.20`, whose normal support period ended April 1, 2026 according to Alpine's [release table](https://alpinelinux.org/releases/). Updating the base and rebuilding improves access to OS fixes, but does not establish that the completed image is vulnerability-free.

## Build the runtime image

Install the package to an isolated prefix, then copy that prefix into the final stage. This avoids shipping `pip`, `setuptools`, and other build-only files.

```dockerfile
FROM python:3.12-alpine3.20 AS build
WORKDIR /sslyze
COPY . .
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-alpine3.20
COPY --from=build /install /usr/local
RUN adduser -D -H -u 1001 -s /sbin/nologin sslyze
USER sslyze
ENTRYPOINT ["sslyze"]
CMD ["-h"]
```

Build the Alpine and Debian-slim images from the same checkout, then inspect their sizes and exercise the CLI:

```bash
podman build -f Dockerfile.alpine-build -t sslyze:alpine-build .
podman build -f Dockerfile -t sslyze:slim-build .
podman images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"

podman run --rm sslyze:alpine-build -h
podman run --rm --entrypoint id sslyze:alpine-build
podman run --rm sslyze:alpine-build badssl.com
```

Use a host that actually serves TLS. `scanme.nmap.org` rejected the TLS connection in our test, while `badssl.com` completed normally. `badssl.com` is intentionally built for TLS testing.[1]

By default, SSLyze runs the Mozilla intermediate compliance check when no scan commands are selected. If selecting commands explicitly, add the profile to retain that check:

```bash
podman run --rm sslyze:alpine-build --mozilla_config=intermediate badssl.com
```

Use `--mozilla_config=disable` to turn off the default compliance check.

## Validate a registry path locally

A direct local build and run does not test a registry push or pull. The following uses a disposable local registry, then removes it after the test. `--tls-verify=false` is limited to this insecure `localhost:5000` registry.

```bash
podman run -d --name registry -p 5000:5000 --replace docker.io/library/registry:2
podman tag localhost/sslyze:alpine-build localhost:5000/sslyze:alpine-build
podman push --tls-verify=false localhost:5000/sslyze:alpine-build
podman pull --tls-verify=false localhost:5000/sslyze:alpine-build
podman run --rm localhost:5000/sslyze:alpine-build -h
podman rm -f registry
```

The test verifies that the image can be pulled and run without relying on the local build cache. The next step is to run the image in CI and retain the benchmark output as an artifact.

[1]: `badssl.com` is an intentionally misconfigured test target for TLS tooling.
