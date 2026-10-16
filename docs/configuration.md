# Configuration Reference

This document provides a comprehensive reference for all configuration mechanisms across `service-portals`, including `PortalRule` definitions, environment variables, command-line flags, and caching.

---

## `PortalRule` Specification

The `all-in-one-portal` routes incoming requests dynamically based on YAML rule definitions. These rules map incoming `Host` headers to upstream API targets, inject credentials, and configure caching.

### Example Multi-Rule Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: portal-rules-secret
stringData:
  rules.yaml: |
    apiVersion: portals.gke.io/v1alpha1
    kind: PortalRule
    metadata:
      name: gemini
    spec:
      host: gemini.backend
      rewriteUrl: https://generativelanguage.googleapis.com
      authToken: AIzaSyYourGeminiApiKey
      authHeader: x-goog-api-key
      cacheTTL: 10m
    ---
    apiVersion: portals.gke.io/v1alpha1
    kind: PortalRule
    metadata:
      name: github
    spec:
      host: github.backend
      rewriteUrl: https://api.github.com
      authToken: ghp_YourGitHubToken
      authHeader: Authorization
    ---
    apiVersion: portals.gke.io/v1alpha1
    kind: PortalRule
    metadata:
      name: anthropic
    spec:
      host: anthropic.backend
      rewriteUrl: https://api.anthropic.com
      authToken: sk-ant-YourAnthropicKey
      authHeader: x-api-key
```

### Field Reference

| Field | Type | Required | Description | Default |
| :--- | :--- | :--- | :--- | :--- |
| `apiVersion` | `string` | **Yes** | Must be `portals.gke.io/v1alpha1`. | None |
| `kind` | `string` | **Yes** | Must be `PortalRule`. Documents with any other kind are ignored. | None |
| `metadata.name` | `string` | No | Identifier for the rule, used in proxy logging. | `""` |
| `spec.host` | `string` | **Yes** | Incoming hostname to match against the request `Host` header (or URL host). Matching is case-insensitive. Port numbers (e.g., `:80`, `:443`) are stripped before matching. If empty, the rule is skipped with a warning. | None |
| `spec.rewriteUrl` | `string` | No | Target upstream URL. If omitted, defaults to `spec.host`. If no URL scheme is provided, `https://` is automatically prepended. | `https://<spec.host>` |
| `spec.authToken` | `string` | No | Real upstream authentication credential to inject into requests. | `""` |
| `spec.authHeader` | `string` | No | Header name to inject `spec.authToken` into. If set to `Authorization` (or omitted), the header value is formatted as `Bearer <authToken>`. For all other header names (e.g., `x-api-key`, `x-goog-api-key`), the raw token string is injected directly without the `Bearer ` prefix. | `Authorization` |
| `spec.cacheTTL` | `string` | No | Go duration string (e.g. `5m`, `1h`, `30s`). If set, enables in-memory response caching for GET requests matching this rule. | `""` (no caching) |

### Rule Loading Semantics
- **Directory Traversal**: The proxy walks the directory specified by `--rules-dir` (or `RULES_DIR`) recursively (`filepath.WalkDir`).
- **File Extensions**: Only files ending in `.yaml` or `.yml` (case-insensitive) are read. All other files (e.g. `.json`, `.txt`, `.tmp`) are ignored.
- **Multi-document YAML**: Files can contain multiple YAML documents separated by `---`.
- **Dynamic Reload via `SIGHUP`**: The proxy listens for the `SIGHUP` signal. When received, it re-scans the rules directory and rebuilds the routing table in-memory without dropping existing connections or terminating the process.

### Fallback & Unmatched Host Behavior
When `--rules-dir` / `RULES_DIR` is set:
1. **Default Egress Allowlist (No Fallback)**: By default, the proxy operates as a strict egress allowlist. If an incoming request arrives for a host that does **not** match any loaded `PortalRule`, the request is rejected:
   - **HTTP**: The proxy responds with HTTP `403 Forbidden` (`Access Denied: host not allowed by portal rules`) and logs `Request: <METHOD> <HOST> | Matched rule: <none> | Action: denied`.
   - **HTTPS**: Dynamic certificate generation refuses to sign a certificate for unmatched hosts (`GetCertificate` returns an error), causing the client TLS handshake to fail.
2. **Explicit Fallback Proxy**: If `TARGET_URL` is explicitly set in the environment, fallback behavior is enabled:
   - Unmatched requests fall through to the fallback proxy, rewritten to `TARGET_URL` with `UPSTREAM_AUTH_TOKEN` (if configured), and log `Request: <METHOD> <HOST> | Matched rule: <none> | Action: fallback`.
   - For HTTPS, the fallback proxy's CA signer mints a dynamic certificate.
3. **No Rules Directory (`service-portal`, `gemini-portal`, etc.)**: When no rules directory is configured, the proxy forwards all traffic to `TARGET_URL` (defaulting to the portal's default target URL, e.g. Gemini).

Note that once a rules directory is configured, `config.DefaultTargetURL` (what `gemini-portal`, `anthropic-portal`, and `github-portal` set) is intentionally ignored so that the proxy strictly enforces the rule allowlist rather than silently falling back to a default provider endpoint. Fallback to an upstream target is only enabled when `TARGET_URL` is explicitly set via the environment.

---

## Environment Variables & Flags

### 1. Service Portals (`all-in-one-portal`, `service-portal`, `gemini-portal`, `anthropic-portal`, `github-portal`)

These variables configure the HTTP/HTTPS proxy servers.

| Variable / Flag | Default | Description |
| :--- | :--- | :--- |
| `PORT` | `8080` | Port to listen on for standard HTTP requests and transparently redirected port 80 traffic. |
| `HTTPS_PORT` | `8443` | Port to listen on for TLS connections and transparently redirected port 443 traffic. Always started; if `CA_CERT_PATH` and `CA_KEY_PATH` are not configured, the listener is active but incoming TLS handshakes fail with a certificate signing error. |
| `RULES_DIR` / `--rules-dir` | `""` | Directory containing `PortalRule` YAML files. The `--rules-dir` flag takes precedence over the environment variable. |
| `TARGET_URL` | *See below* | Fallback / default target URL. With a rules directory (`--rules-dir` / `RULES_DIR`), both `all-in-one-portal` and `service-portal` (as well as provider-specific portals) deny unmatched hosts unless `TARGET_URL` is explicitly set in the environment. Without a rules directory, defaults to:<br>• `service-portal` & `all-in-one-portal`: `https://generativelanguage.googleapis.com`<br>• `gemini-portal`: `https://generativelanguage.googleapis.com`<br>• `anthropic-portal`: `https://api.anthropic.com`<br>• `github-portal`: `https://api.github.com/` |
| `UPSTREAM_AUTH_TOKEN` | `""` | Default token injected into requests when falling through to `TARGET_URL`. |
| `UPSTREAM_AUTH_HEADER` | *See below* | Header used for `UPSTREAM_AUTH_TOKEN`. Defaults: <br>• `gemini-portal`: `x-goog-api-key`<br>• `anthropic-portal`: `x-api-key`<br>• `service-portal`, `all-in-one-portal`, `github-portal`: `Authorization` |
| `CA_CERT_PATH` | `""` | Path to public Root CA certificate PEM file (`tls.crt`). Required for TLS interception and dynamic cert minting. |
| `CA_KEY_PATH` | `""` | Path to Root CA private key PEM file (`tls.key`). Must be readable by the proxy UID (`1337`). |
| `CACHE_TTL` | `""` | Global fallback cache TTL duration string (e.g. `10m`, `1h`). |
| `CACHE_CLEANUP_INTERVAL` | `1m` | Frequency at which the background cache janitor cleans up expired in-memory cache items. |
| `OTEL_INSTRUMENTATION_ENABLED` | `""` | Set to `"true"` to enable built-in OpenTelemetry HTTP server and client instrumentation (W3C trace context propagation). |

---

### 2. Init Container (`init-service-portals`)

Configured via environment variables on the `init-service-portals` container and command-line flags on the `/usr/local/bin/init-service-portals` binary.

#### Environment Variables (`entrypoint.sh`)

| Variable | Default | Description |
| :--- | :--- | :--- |
| `PROXY_PORT` | `8080` | Local port to which intercepted HTTP traffic is redirected. |
| `PROXY_HTTPS_PORT` | `8443` | Local port to which intercepted HTTPS traffic (port 443) is redirected. |
| `PROXY_UID` | `1337` | UID of the proxy container. Outbound packets owned by this UID are bypassed in NAT and allowed outbound in egress filtering. |
| `INTERCEPT_PORTS` | `80` | Comma-separated list of TCP ports to redirect (e.g. `80,443`), or `*` for wildcard interception (redirects 443 to `PROXY_HTTPS_PORT` and all other ports to `PROXY_PORT`). |
| `CA_DIR` | `/etc/service-portal/ca` | Destination directory where the public CA certificate (`tls.crt`) is written. Mounted to the workload container. |
| `CA_PRIVATE_DIR` | `/etc/service-portal/ca-private` | Destination directory where the CA certificate (`tls.crt`) and private key (`tls.key`) are written. Mounted only to the proxy container. |
| `CHOWN_UID` | `-1` | UID to chown the `CA_PRIVATE_DIR` and `tls.key` to. In sidecar mode, set to `1337`. (`-1` leaves unchanged). |
| `CHOWN_GID` | `-1` | GID to chown the `CA_PRIVATE_DIR` and `tls.key` to. In sidecar mode, set to `1337`. (`-1` leaves unchanged). |
| `DNS_SERVER_IPS` | Nameservers from `/etc/resolv.conf` | Comma-separated list of DNS server IP addresses allowed for outbound DNS requests (UDP/TCP port 53). Restricts DNS to designated resolvers (e.g. cluster DNS) to prevent DNS tunnelling. |
| `ALLOW_METADATA` | `false` | When `false`, explicitly blocks access to cloud metadata IP ranges (`169.254.0.0/16`, AWS `fd00:ec2::254`, GCE `fd20:ce::254`, and link-local `fe80::/10`) before any allowlist rules. Set to `true` to opt into allowing metadata server access. |
| `ALLOW_CIDRS` | `""` (empty) | Comma-separated list of IPv4 and IPv6 CIDRs the workload may reach directly without proxy interception or egress rejection (e.g. cluster service CIDRs). |
| `ALLOW_PORTS` | `""` (empty) | Comma-separated list of additional TCP destination ports the workload may reach directly. |
| `EGRESS_ACTION` | `REJECT` | Action to take when outbound traffic is not allowed: `REJECT` (fast failure with ICMP port unreachable) or `DROP` (silent packet drop). |
| `ALLOW_UNFILTERED_IPV6` | `false` | When `false`, failure to apply `ip6tables` rules when IPv6 is enabled in the network namespace causes init to fail closed (`exit 1`). Set to `true` only as an escape hatch to allow container startup without IPv6 filtering. |

> **Note on Egress Filtering & Idempotency**: Egress rules are applied via atomic full-table replaces with `iptables-restore` and `ip6tables-restore` using dedicated custom chains `PORTAL_OUTPUT` (in `nat`) and `PORTAL_EGRESS` (in `filter`), guaranteeing idempotency across restarts while replacing any pre-existing `nat` or `filter` rules in the pod's network namespace. Essential kernel ICMP/ICMPv6 control messages (IPv4 types 0, 3, 11; IPv6 types 1-4 and Neighbor Discovery 133-137) are allowed, while workload ping requests (`echo-request`) and unpermitted TCP/UDP egress are rejected. The effective ruleset is logged (`iptables-save`, `ip6tables-save`) on startup.

#### CLI Flags (`cmd/init-service-portals`)

```
/usr/local/bin/init-service-portals [flags]
```

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-cert-dir` | `/etc/service-portal/ca` | Directory to write the public CA certificate (`tls.crt`). |
| `-key-dir` | `/etc/service-portal/ca-private` | Directory to write the private key (`tls.key`) and certificate (`tls.crt`). |
| `-chown-uid` | `-1` | UID to chown the private key file and directory to. |
| `-chown-gid` | `-1` | GID to chown the private key file and directory to. |

---

### 3. Git Proxy Server (`cmd/gitproxy-server`)

The Git caching proxy supports command-line flags and environment variables. Flags take precedence over environment variables.

| Flag | Environment Variable | Default | Description |
| :--- | :--- | :--- | :--- |
| `--port` | `PORT` | `8080` | Port to listen on for Git HTTP requests. |
| `--target-url` | `TARGET_URL` | `""` | Default upstream target URL for relative Git paths. |
| `--cache-dir` | `CACHE_DIR` | `""` | Directory for disk-backed packfile and response caching. If omitted, uses in-memory cache. |
| `--cache-ttl` | `CACHE_TTL` | `168h` (7 days) | Cache time-to-live duration string (e.g. `24h`, `7d`). |
| `--cache-cleanup-interval` | `CACHE_CLEANUP_INTERVAL` | `10m` | Interval at which expired items are purged from the cache. |
| `--upstream-auth-token` | `UPSTREAM_AUTH_TOKEN` | `""` | Authentication token injected into upstream Git requests. |
| `--upstream-auth-header` | `UPSTREAM_AUTH_HEADER` | `Authorization` | Header used for injecting the authentication token into upstream Git requests. |
| — | `OTEL_INSTRUMENTATION_ENABLED` | `""` | Set to `"true"` to enable OpenTelemetry transport instrumentation. |

---

## Caching Behavior

`service-portals` provides two levels of caching:

### 1. HTTP Response Caching (`pkg/cache`)
- **In-Memory Cache (`cache.InMemoryCache`)**: Thread-safe in-memory map storing serialized response headers and bodies with an expiration timestamp. Managed by a periodic background janitor.
- **Disk Cache (`cache.DiskCache`)**: Filesystem-backed cache storing objects named by SHA-256 hash. Supports streaming reads and writes via temporary files and atomic rename. Updates file modification times on read access and removes files older than TTL during janitor sweeps.
- **Rule Activation**: Response caching is enabled on a per-rule basis by specifying `spec.cacheTTL` in a `PortalRule`, or globally via `CACHE_TTL`. Caching only applies to cacheable HTTP methods (GET).

### 2. Git Protocol & Packfile Caching (`pkg/gitproxy`)
`cmd/gitproxy-server` provides intelligent, protocol-aware Git caching:
- Supports Git protocol versions **v0**, **v1**, and **v2**.
- Caches Git references (`/info/refs?service=git-upload-pack`) and Git packfiles (`/git-upload-pack`).
- Resolves Git packfile delta chains (`OFS_DELTA` and `REF_DELTA`) and maintains a directed acyclic graph (DAG) of commit reachability.
- When clients execute incremental `fetch` or `pull` requests sending `have` commits, the proxy analyzes the commit DAG, prunes objects already reachable by the client, dynamically generates an optimized packfile from cache, and pulls only missing commits from upstream.
