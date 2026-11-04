# Agent Guide: Service Portals

`service-portals` is a credential-swapping, layer-7 intercepting proxy designed to secure untrusted and semi-trusted sandboxes (such as AI agents, CI jobs, and code execution runners). It ensures that **real credentials never enter the sandbox container** ("tokens that aren't there can't leak"). Outbound traffic is transparently intercepted, decrypted using an ephemeral pod-local Root CA, matched against routing rules, and forwarded to external APIs with real authentication headers injected.

---

## Codebase Map

### Core Libraries (`pkg/`)
- **`pkg/proxy/`**: The foundational layer-7 proxy (`HTTPProxy`). Handles reverse proxying, request/response header sanitization (RFC 7230 hop-by-hop removal), explicit `HTTP CONNECT` hijacking, dynamic X.509 certificate generation signed by CA key pairs, and OpenTelemetry client transport wrapping.
- **`pkg/portals/`**: The multi-tenant routing engine. Implements `PortalRule` YAML unmarshaling, directory walking, lower-cased host routing, `SIGHUP` live rule reloading, dynamic SNI `GetCertificate` dispatch, and the unified server runner (`Run`).
- **`pkg/cache/`**: Caching infrastructure. Provides `InMemoryCache` and filesystem-backed `DiskCache` with SHA-256 key hashing, streaming file I/O, atomic temporary file replacement, and background janitor expiration sweeps.
- **`pkg/gitproxy/`**: Protocol-aware Git caching. Implements Git Smart HTTP protocols (v0, v1, v2), packfile and delta chain (`OFS_DELTA`, `REF_DELTA`) parsing, commit DAG reachability analysis, and dynamic packfile generation from cache based on client `have` lines.

### Applications (`cmd/` and service directories)
- **`cmd/all-in-one-portal/`**: The primary sidecar proxy binary. Uses `pkg/portals` to load `PortalRule` secrets from `--rules-dir`, listening on `:8080` (HTTP) and `:8443` (HTTPS) with SNI-based dynamic TLS minting.
- **`cmd/init-service-portals/`**: Setup binary for the pod `initContainer`. Generates ephemeral pod-local 2048-bit RSA Root CA key pairs, writes public certs to `/etc/service-portal/ca`, and writes private keys to `/etc/service-portal/ca-private`; executed by `entrypoint.sh` before it sets up iptables redirection and egress filtering.
- **`cmd/gitproxy-server/`**: Standalone caching Git proxy binary supporting disk/memory caches and upstream token injection.
- **`cmd/service-portal/`**: Single-target reverse proxy and HTTP proxy binary.
- **`gemini-portal/`**: Specialized portal for Google Gemini API (`generativelanguage.googleapis.com`) with JSON and gRPC protobuf request/response payload parsing and logging.
- **`anthropic-portal/`**: Specialized portal for Anthropic Messages API (`api.anthropic.com`) with system prompt and message logging, and gzip decompression.
- **`github-portal/`**: Specialized portal for GitHub API (`api.github.com`) with token injection and header redaction.

### Deployments, Tests, & Tasks
- **`k8s/sidecar.yaml`**: Authoritative production manifest for the transparent sidecar pattern (init container + sidecar proxy + workload + Secret rules).
- **`k8s/manifests.yaml`**: Manifest for deploying standalone cluster-wide service mode.
- **`tests/e2e/`**: KinD-based integration tests verifying both standalone service and transparent sidecar TLS interception and credential injection.
- **`dev/ci/presubmits/`**: CI validation scripts: `ap-build`, `ap-test`, `ap-lint`, `ap-verify-generate`, and `ap-e2e`.
- **`dev/tasks/`**: Local development tasks: `deploy-to-kube`, `create-test-certificates`. (E2E tests are executed via `ap e2e .` or `RUN_E2E=1 go test -v ./tests/e2e/...` using ap's built-in Go e2e runner).

---

## Essential Conventions & Architecture Principles

1. **Defense in Depth**: Real tokens live exclusively in Secret volume mounts attached to the proxy UID (`1337`). Workload containers run as non-root (e.g. UID `1000`) with `allowPrivilegeEscalation: false` to ensure they cannot run as UID `1337` and bypass iptables.
2. **Deterministic Interception**: Port 80 traffic redirects to 8080 (HTTP); port 443 redirects to 8443 (HTTPS). Egress filter blocks all other outbound TCP and UDP except DNS (port 53) and proxy UID 1337.
3. **No Code Changes to Applications**: Workloads use standard hostnames (via `hostAliases`) and standard client libraries, trusting only the pod-local public CA certificate.
4. **Verification**: Run `go test ./...` to verify all Go packages. Ensure code passes `dev/ci/presubmits/ap-lint` and `dev/ci/presubmits/ap-test`. Reviewers will read the commit messages, so each commit should explain *why*, and behaviour changes (e.g. fail-closed defaults) must be called out in the commit body.

### Commit messages and PR descriptions

The git history is the permanent record; the GitHub PR description is not. It is not part of the merged artifact and is effectively lost after merge. The PR description is just `Fixes #<issue>`; the commit message carries the why.

- **Put anything worth keeping in the code or the commits**: design decisions and non-obvious behaviour belong in code comments; the reasoning behind a change belongs in the commit message.
- **Keep the PR description to bookkeeping**: normally just `Fixes #<issue>`. Don't summarize or "sell" the change; the code and commits should stand on their own.
- When you revise a PR in response to review, don't maintain a changelog in the PR description.

---

## Scope

- **One idea, one issue, one PR.** If a PR can be split into two ideas, split it; problems found during review that are outside the PR's idea become new issues.
- **A good PR changes at most 200 lines, including tests.** The time to review and understand a PR grows roughly with the square of the lines in the diff, so two 100-line PRs cost a quarter of one 200-line PR. If the one idea needs more than 200 lines, say so on the issue before pushing and propose where to cut or how to order the parts.
- **Issues carry a line budget** for the same reason; an issue without one should be given one before it is assigned.
- **Do not stack unmerged PRs.** Open the next part after the previous one merges; a PR that carries another PR's commits cannot be reviewed on its own.
