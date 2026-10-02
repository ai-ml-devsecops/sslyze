# Alpine vs. Debian-slim for a Python security tool: a sslyze case study

## What we did

The Practical DevSecOps challenge starts with a pipeline that pulls the prebuilt
`hysnsec/sslyze` image. Its task is to read the SSLyze documentation, write a Dockerfile based on
Alpine, and run your own image in CI.

The source project is the official [nabla-c0d3/sslyze repository](https://github.com/nabla-c0d3/sslyze).
In the challenge working copy, we added custom `How to fix:` remediation logging and an
Alpine-based Dockerfile, then built and tested our own image. `hysnsec/sslyze` was used as the
prebuilt lab reference and later as a CI comparison; it was not used as the base image or source
for `flex4lease/sslyze`.

The Codespaces challenge branch is not behind the official project's [`release` branch](https://github.com/nabla-c0d3/sslyze/tree/release); there are no new commits to fetch. The Debian-slim and Alpine sizes below are builds from this same challenge checkout. We did not build from or benchmark the official published
`nablac0d3/sslyze` Docker image.

## Why teams often avoid Alpine for tools like sslyze

This is the standard tradeoff worth naming explicitly, because it's the reason the repo ships a
Debian-slim Dockerfile as the default rather than Alpine:

- **musl vs. glibc.** Alpine uses musl libc instead of glibc. Most Python C-extension packages are
  built and tested against glibc (`manylinux` wheels). `nassl` (sslyze's OpenSSL binding, a C
  extension) and `cryptography` both need musl-compatible (`musllinux`) wheels or a from-source
  build with a compiler toolchain. Historically `nassl` had musl compatibility problems (missing
  symbols at runtime), which is a real, citable risk for this specific tool.
- **Long-term stability/support.** glibc/Debian is the more heavily tested target for the Python
  crypto/TLS ecosystem. Teams that prioritize predictable upgrades and vendor/CVE tooling
  familiarity often default to Debian-slim even at a size cost, because a musl-related runtime
  failure (e.g. a missing `musllinux` wheel forcing a source build) is a worse outcome than a
  larger image.
- **The tradeoff in the other direction.** Sticking with Debian-slim means a larger base OS,
  more installed packages, and a correspondingly larger inherited CVE surface — the opposite
  problem. There's no free lunch: smaller/musl gets you size and a narrower package surface;
  glibc/slim gets you wheel compatibility and ecosystem maturity.

For this repo, at Python 3.12 / linux-x86_64, both `nassl` and `cryptography` publish current
`musllinux` wheels, so the historical compatibility risk didn't materialize — no compiler or
`apk` build dependencies were needed. That won't automatically be true on every architecture or
Python version, so it's worth re-checking wheel availability before committing to Alpine in a
pipeline that must run on ARM or a newer/older Python.

## Verifying the target works before blaming the tool

`podman run --rm sslyze:alpine-build scanme.nmap.org` returned "connection rejected." Confirmed
independently with `curl -sv https://scanme.nmap.org/` → connection refused. That host doesn't
serve HTTPS on 443 at all (it's an Nmap HTTP/SSH test target, not a TLS one). Switched to
`badssl.com`, a host built specifically for TLS testing, and the scan completed normally.

## When remediation guidance appears

The remediation lookup runs when SSLyze checks scan results against a TLS profile. With no scan
commands explicitly selected, SSLyze enables the Mozilla intermediate profile by default. If you explicitly select
scan commands and also want the compliance check, request the profile with `--mozilla_config`:

```bash
podman run --rm sslyze:alpine-build --mozilla_config=intermediate badssl.com
```

To disable the default profile check, pass `--mozilla_config=disable`. If you explicitly enable
individual scan commands without selecting a TLS profile, the compliance section is disabled;
that is a command-selection behavior, not a missing feature in the image.

## Tightening the Alpine build

The initial `Dockerfile.alpine-build` copied all of `site-packages`; installing to an isolated
prefix and copying that into the runtime image avoids carrying `pip`, `setuptools`, `wheel`, and
build metadata that are not needed at runtime.

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

`adduser -D -H -u 1001 -s /sbin/nologin` is BusyBox's documented short-option syntax (no home dir,
no password, fixed UID, no login shell) — functionally equivalent to the long-option form, but
matches what's actually documented for Alpine's `adduser`.

This is now the content of `Dockerfile.alpine-build` in the repo.

## Keeping the Alpine base current

The image and benchmark in this walkthrough were built from `python:3.12-alpine3.20`. Alpine
3.20's normal support period ended on April 1, 2026, according to the [official Alpine release
table](https://alpinelinux.org/releases/). The challenge requirement is to use Alpine;
it does not require staying on this release. For ongoing use, move both Dockerfile stages to a
currently supported Python 3.12 Alpine tag, rebuild, and rerun the functional and CI checks. A
supported base improves the chance of receiving OS security fixes, but it does not by itself
prove the finished image is vulnerability-free.

## Final size comparison

| Image | Base | Final size |
|---|---|---|
| `sslyze:slim-build` (`Dockerfile`) | `python:3.12-slim` | 177 MB |
| `sslyze:alpine-build` (`Dockerfile.alpine-build`, updated) | `python:3.12-alpine3.20` | 86.1 MB |

~51% smaller than the stock Debian-slim build, with no extra build dependencies needed for this
Python version/architecture.

## Testing locally with a local registry

Building and running images directly with `podman build`/`podman run` is fine for a single host,
but doesn't validate the things a real deployment pipeline depends on: pushing to a registry,
pulling by digest, and running from a pulled image rather than the local build cache. Standard
local-dev practice is to stand up a throwaway registry and push/pull through it before wiring up
CI:

```bash
# Run a local registry (ephemeral, port 5000)
podman run -d --name registry -p 5000:5000 --replace docker.io/library/registry:2

# Tag and push the image to it
podman tag localhost/sslyze:alpine-build localhost:5000/sslyze:alpine-build
podman push --tls-verify=false localhost:5000/sslyze:alpine-build

# Pull it back down (simulating a separate consumer/host) and run from the pulled image
podman pull --tls-verify=false localhost:5000/sslyze:alpine-build
podman run --rm localhost:5000/sslyze:alpine-build -h

# Tear down when done
podman rm -f registry
```

This catches issues that a local `build`+`run` won't: registry auth/config problems, missing
`--tls-verify` flags for insecure local registries, and confirming the image is self-contained
(no accidental dependency on files left over in the build-stage cache).

## Reproduce from scratch

```bash
git clone --branch codespace-shiny-space-enigma-5vvgpx5v67pc9qg \
  https://github.com/ai-ml-devsecops/sslyze.git
cd sslyze

# This challenge working copy is based on the official nabla-c0d3/sslyze project.
# It contains the custom remediation change and Alpine Dockerfile used below.

podman build -f Dockerfile.alpine-build -t sslyze:alpine-build .
podman build -f Dockerfile -t sslyze:slim-build .
podman images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"

podman run --rm sslyze:alpine-build -h
podman run --rm --entrypoint id sslyze:alpine-build
podman run --rm sslyze:alpine-build badssl.com
podman run --rm sslyze:alpine-build --mozilla_config=intermediate badssl.com

podman image prune -f   # drop dangling intermediate build-stage images
```
