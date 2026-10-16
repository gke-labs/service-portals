# All-In-One Portal (`cmd/all-in-one-portal`)

`all-in-one-portal` is the primary multi-service proxy server. It is typically deployed as a sidecar container in sandboxed pods to handle transparent HTTP and HTTPS interception, dynamic TLS certificate minting, host-based routing, and credential swapping.

---

## Features

- **Embedded DNS Server**: Serves DNS on `127.0.0.1:53` (UDP and TCP), resolving policy hosts to the proxy's dedicated loopback address (`127.0.0.2`), answering `NXDOMAIN` for unlisted domains, and forwarding when `DEFAULT_ACTION=Allow`.
- **Dynamic Rule Routing**: Reads `PortalRule` resources from a directory (`--rules-dir` flag or `RULES_DIR` env var). Matches requests by `Host` header to determine target upstream URLs and authentication tokens.
- **Dynamic SNI TLS Termination**: Listens on `HTTPS_PORT` (`:8443` or `:443`). Inspects SNI in the TLS ClientHello and dynamically mints and caches TLS certificates signed by the local CA (`CA_CERT_PATH`, `CA_KEY_PATH`).
- **Live Rule Reloading**: Reloads configuration files dynamically upon receiving a `SIGHUP` signal without process restarts or dropping active connections.
- **Per-Rule Caching**: Supports rule-level caching via `spec.cacheTTL` on individual `PortalRule` objects, backed by an in-memory cache.
- **OpenTelemetry Instrumentation**: Supports W3C trace context extraction and propagation when `OTEL_INSTRUMENTATION_ENABLED=true`.

---

## Configuration

### Command-Line Flags
- `--rules-dir`: Directory containing `PortalRule` YAML files.
- `--serve-dns`: Serve DNS for configured rule hosts (default `true`).
- `--dns-bind-addr`: Address to bind DNS server (default `127.0.0.1:53`).
- `--proxy-bind-addr`: Address to bind HTTP/HTTPS proxy (default `127.0.0.2`).
- `--default-action`: Default action for unconfigured DNS hosts (`Deny` or `Allow`, default `Deny`).

### Key Environment Variables
- `PORT`: HTTP listen port (default `8080`).
- `HTTPS_PORT`: HTTPS listen port (default `8443`).
- `PROXY_BIND_ADDR`: Dedicated loopback bind address (default `127.0.0.2`).
- `SERVE_DNS`: Set to `"false"` to disable embedded DNS server.
- `DNS_BIND_ADDR`: Address to bind DNS server (default `127.0.0.1:53`).
- `DEFAULT_ACTION`: Action for unconfigured hosts in DNS: `Deny` (default, returns `NXDOMAIN`) or `Allow` (forwards to upstream DNS).
- `UPSTREAM_DNS_SERVERS`: Comma-separated list of cluster DNS resolvers for upstream proxy dialer and DNS forwarding (default discovered from `/etc/service-portal/upstream-resolv.conf` or `/etc/resolv.conf`).
- `RULES_DIR`: Directory containing `PortalRule` YAML files (overridden by `--rules-dir`).
- `CA_CERT_PATH`: Path to Root CA certificate PEM file.
- `CA_KEY_PATH`: Path to Root CA private key PEM file.
- `TARGET_URL`: Default fallback upstream URL.
- `UPSTREAM_AUTH_TOKEN`: Default fallback authentication token.
- `UPSTREAM_AUTH_HEADER`: Default fallback authentication header (default `Authorization`).
- `CACHE_TTL`: Global fallback cache TTL duration.
- `CACHE_CLEANUP_INTERVAL`: Interval for clearing expired cache items (default `1m`).
- `OTEL_INSTRUMENTATION_ENABLED`: Set to `"true"` to enable OpenTelemetry tracing.
