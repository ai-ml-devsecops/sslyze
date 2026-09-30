# Alpine vs. Debian-slim for a Python security tool: a sslyze case study

## What we did

Built `sslyze` (a TLS/SSL scanner) from a feature branch into a container image, validated it
against a live target, confirmed a specific commit's behavior, and compared the repo's stock
`Dockerfile` (Debian-slim) against an Alpine-based build — then tightened the Alpine build further.

Repo: `https://github.com/ai-ml-devsecops/sslyze`, branch `codespace-shiny-space-enigma-5vvgpx5v67pc9qg`

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

## Confirming a code change shipped and knowing when it activates

Commit `5eac10f` added a `how_to_fix` remediation lookup and a print statement in `__main__.py`.
Both are present in the built image, but only execute when the Mozilla compliance check is
explicitly enabled:

```bash
podman run --rm sslyze:alpine-build --mozilla_config=intermediate badssl.com
```

Without `--mozilla_config` or `--custom_tls_config`, that whole branch is skipped and prints
"Disabled" — not a build issue, just an opt-in feature flag.

## Tightening the Alpine build

The original `Dockerfile.alpine-build` copied the entire `site-packages` directory from the build
stage into the runtime stage, which drags along `pip`, `setuptools`, `wheel`, and build metadata
that add nothing at runtime. Installing to an isolated prefix and copying only that avoids it:

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

podman build -f Dockerfile.alpine-build -t sslyze:alpine-build .
podman build -f Dockerfile -t sslyze:slim-build .
podman images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"

podman run --rm sslyze:alpine-build -h
podman run --rm --entrypoint id sslyze:alpine-build
podman run --rm sslyze:alpine-build badssl.com
podman run --rm sslyze:alpine-build --mozilla_config=intermediate badssl.com

podman image prune -f   # drop dangling intermediate build-stage images
```
