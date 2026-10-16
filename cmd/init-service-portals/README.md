# Init Service Portals (`cmd/init-service-portals`)

`init-service-portals` is the setup utility packaged into the `init-service-portals` container image. It runs as an `initContainer` inside the pod to establish pod-local TLS trust and configure network packet redirection and egress filtering.

---

## Responsibilities

1. **Pod-Local Root CA Generation**: Generates an ephemeral 2048-bit RSA Root Certificate Authority (`tls.crt` and `tls.key`) with a 10-year validity period.
2. **Key Privilege Separation**:
   - Writes the public certificate (`tls.crt`) into the cert directory (`-cert-dir`, default `/etc/service-portal/ca`), which is mounted read-only to the workload container.
   - Writes the private key (`tls.key`) with `0600` permissions and certificate into the key directory (`-key-dir`, default `/etc/service-portal/ca-private`), and chowns both directory and key file to the proxy user (`-chown-uid` and `-chown-gid`, typically `1337`).
3. **iptables Interception & Egress Enforcement (`entrypoint.sh`)**:
   - Applied via atomic full-table replaces with `iptables-restore` and `ip6tables-restore` using dedicated custom chains `PORTAL_OUTPUT` (in `nat`) and `PORTAL_EGRESS` (in `filter`), guaranteeing idempotency across restarts while replacing any pre-existing `nat` or `filter` rules in the pod's network namespace.
   - Fail-closed IPv6: If IPv6 is disabled in the network namespace (`/proc/sys/net/ipv6/conf/all/disable_ipv6=1`), IPv6 rules are skipped with an info log. Otherwise, failure to restore `ip6tables` rules is fatal (`exit 1`), preventing unfiltered IPv6 egress unless explicitly opted out with `ALLOW_UNFILTERED_IPV6=true`.
   - Redirects configured TCP ports (e.g. 80 and 443, or `*`) to proxy ports (8080 HTTP, 8443 HTTPS).
   - Excludes proxy UID 1337 and loopback from redirection and egress blocking.
   - Restricts DNS (UDP/TCP port 53) to configured DNS servers (`DNS_SERVER_IPS`, defaults to nameservers discovered in `/etc/resolv.conf`), preventing exfiltration via arbitrary DNS resolvers.
   - Allows essential kernel-generated ICMP and ICMPv6 control messages:
     - IPv4: destination-unreachable (3), time-exceeded (11), and echo-reply (0).
     - IPv6: error messages 1-4 (destination unreachable, packet too big, time exceeded, parameter problem) and Neighbor Discovery types 133-137 (RS, RA, NS, NA, redirect).
   - Metadata and link-local blocking: Blocks cloud metadata IP ranges (IPv4 `169.254.0.0/16`, AWS IMDS `fd00:ec2::254/128`, GCE metadata `fd20:ce::254/128`) and IPv6 link-local destinations (`fe80::/10`, covering Azure WireServer at `fe80::1234:5678:9abc`) by default *after* Neighbor Discovery and *before* any allowlist rules. Metadata access can be opted into via `ALLOW_METADATA=true`.
   - Direct allowlists: Permits direct egress for configured CIDRs (`ALLOW_CIDRS`) and additional TCP ports (`ALLOW_PORTS`).
   - Workload ICMP handling: Rejects outbound ping requests (`echo-request`) from the workload while allowing loopback and proxy UID traffic.
   - Configurable egress action: Rejects with ICMP port unreachable by default (`EGRESS_ACTION=REJECT`) for fast, debuggable failure, or silently drops packets (`EGRESS_ACTION=DROP`).
   - Logs effective rules: Runs `iptables-save` and `ip6tables-save` at the end of initialization for observability in `kubectl logs -c init-service-portals`.

---

## CLI Flags

```
init-service-portals [flags]
```

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-cert-dir` | `/etc/service-portal/ca` | Destination directory for public CA certificate (`tls.crt`). |
| `-key-dir` | `/etc/service-portal/ca-private` | Destination directory for CA certificate and private key (`tls.key`). |
| `-chown-uid` | `-1` | UID to chown private key and directory to (-1 leaves unchanged). |
| `-chown-gid` | `-1` | GID to chown private key and directory to (-1 leaves unchanged). |

---

## Environment Variables (`entrypoint.sh`)

| Variable | Default | Description |
| :--- | :--- | :--- |
| `PROXY_PORT` | `8080` | Local port for HTTP traffic redirection. |
| `PROXY_HTTPS_PORT` | `8443` | Local port for HTTPS traffic redirection. |
| `PROXY_UID` | `1337` | UID of the proxy container, excluded from redirection and allowed outbound. |
| `INTERCEPT_PORTS` | `80` | Ports to redirect (e.g. `80,443`), or `*` for all ports. |
| `CA_DIR` | `/etc/service-portal/ca` | Passed to `-cert-dir`. |
| `CA_PRIVATE_DIR` | `/etc/service-portal/ca-private` | Passed to `-key-dir`. |
| `CHOWN_UID` | `-1` | Passed to `-chown-uid`. |
| `CHOWN_GID` | `-1` | Passed to `-chown-gid`. |
| `DNS_SERVER_IPS` | Nameservers from `/etc/resolv.conf` | Comma-separated list of DNS server IP addresses allowed for outbound DNS requests (UDP/TCP port 53). Restricts DNS to designated resolvers (e.g. cluster DNS) to prevent DNS tunnelling. |
| `ALLOW_METADATA` | `false` | When `false`, explicitly blocks access to cloud metadata IP ranges (`169.254.0.0/16`, AWS `fd00:ec2::254`, GCE `fd20:ce::254`, and link-local `fe80::/10`) before any allowlist rules. Set to `true` to opt into allowing metadata server access. |
| `ALLOW_CIDRS` | `""` (empty) | Comma-separated list of IPv4 and IPv6 CIDRs the workload may reach directly without proxy interception or egress rejection (e.g. cluster service CIDRs). |
| `ALLOW_PORTS` | `""` (empty) | Comma-separated list of additional TCP destination ports the workload may reach directly. |
| `EGRESS_ACTION` | `REJECT` | Action to take when outbound traffic is not allowed: `REJECT` (fast failure with ICMP port unreachable) or `DROP` (silent packet drop). |
| `ALLOW_UNFILTERED_IPV6` | `false` | When `false`, failure to apply `ip6tables` rules when IPv6 is enabled in the network namespace causes init to fail closed (`exit 1`). Set to `true` only as an escape hatch to allow container startup without IPv6 filtering. |
