#!/bin/sh
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -eu

PROXY_PORT=${PROXY_PORT:-8080}
PROXY_HTTPS_PORT=${PROXY_HTTPS_PORT:-8443}
PROXY_UID=${PROXY_UID:-1337}
INTERCEPT_PORTS=${INTERCEPT_PORTS:-80}
CA_DIR=${CA_DIR:-/etc/service-portal/ca}
CA_PRIVATE_DIR=${CA_PRIVATE_DIR:-/etc/service-portal/ca-private}
CHOWN_UID=${CHOWN_UID:--1}
CHOWN_GID=${CHOWN_GID:--1}
ALLOW_METADATA=${ALLOW_METADATA:-false}
ALLOW_CIDRS=${ALLOW_CIDRS:-}
ALLOW_PORTS=${ALLOW_PORTS:-}
EGRESS_ACTION=${EGRESS_ACTION:-REJECT}
RESOLV_CONF=${RESOLV_CONF:-/etc/resolv.conf}
IPV6_DISABLE_PATH=${IPV6_DISABLE_PATH:-/proc/sys/net/ipv6/conf/all/disable_ipv6}
ALLOW_UNFILTERED_IPV6=${ALLOW_UNFILTERED_IPV6:-false}
TEST_FAIL_IP6TABLES=${TEST_FAIL_IP6TABLES:-false}

is_ipv6() {
  case "$1" in
    *:*) return 0 ;;
    *) return 1 ;;
  esac
}

is_ipv6_disabled() {
  if [ -f "${IPV6_DISABLE_PATH}" ]; then
    val=$(cat "${IPV6_DISABLE_PATH}" 2>/dev/null || echo "0")
    if [ "$val" = "1" ]; then
      return 0
    fi
  fi
  return 1
}

resolve_dns_ips() {
  if [ -n "${DNS_SERVER_IPS:-}" ]; then
    echo "${DNS_SERVER_IPS}"
  elif [ -f "${RESOLV_CONF}" ]; then
    grep -E '^\s*nameserver\s+' "${RESOLV_CONF}" | awk '{print $2}' | tr '\n' ',' | sed 's/,$//'
  else
    echo ""
  fi
}

generate_rules() {
  family="$1"

  action=$(echo "${EGRESS_ACTION}" | tr '[:lower:]' '[:upper:]')
  if [ "$action" = "DROP" ]; then
    v4_target="DROP"
    v6_target="DROP"
  else
    v4_target="REJECT --reject-with icmp-port-unreachable"
    v6_target="REJECT --reject-with icmp6-port-unreachable"
  fi

  if [ "$family" = "4" ] || [ "$family" = "v4" ]; then
    family="4"
    target="$v4_target"
    localhost="127.0.0.1/32"
  else
    family="6"
    target="$v6_target"
    localhost="::1/128"
  fi

  # ==================== NAT Table ====================
  echo "*nat"
  echo ":PREROUTING ACCEPT [0:0]"
  echo ":INPUT ACCEPT [0:0]"
  echo ":OUTPUT ACCEPT [0:0]"
  echo ":POSTROUTING ACCEPT [0:0]"
  echo ":PORTAL_OUTPUT - [0:0]"
  echo "-A OUTPUT -p tcp -j PORTAL_OUTPUT"
  echo "-A PORTAL_OUTPUT -o lo -j RETURN"
  echo "-A PORTAL_OUTPUT -m owner --uid-owner ${PROXY_UID} -j RETURN"

  if [ "${INTERCEPT_PORTS}" = "*" ]; then
    echo "-A PORTAL_OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports ${PROXY_HTTPS_PORT}"
    echo "-A PORTAL_OUTPUT -p tcp ! --dport 443 -j REDIRECT --to-ports ${PROXY_PORT}"
  else
    for port in $(echo "${INTERCEPT_PORTS}" | tr ',' ' '); do
      if [ -n "$port" ]; then
        if [ "$port" = "443" ]; then
          echo "-A PORTAL_OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports ${PROXY_HTTPS_PORT}"
        else
          echo "-A PORTAL_OUTPUT -p tcp --dport ${port} -j REDIRECT --to-ports ${PROXY_PORT}"
        fi
      fi
    done
  fi
  echo "COMMIT"

  # ==================== Filter Table ====================
  echo "*filter"
  echo ":INPUT ACCEPT [0:0]"
  echo ":FORWARD ACCEPT [0:0]"
  echo ":OUTPUT ACCEPT [0:0]"
  echo ":PORTAL_EGRESS - [0:0]"
  echo "-A OUTPUT -j PORTAL_EGRESS"

  # 1. Allow all loopback traffic
  echo "-A PORTAL_EGRESS -o lo -j ACCEPT"

  # 2. Allow all traffic to localhost (covers local connections to proxy ports)
  echo "-A PORTAL_EGRESS -d ${localhost} -j ACCEPT"

  # 3. Allow established and related connections
  echo "-A PORTAL_EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"

  # 4. Allow all outbound traffic originating from proxy user
  echo "-A PORTAL_EGRESS -m owner --uid-owner ${PROXY_UID} -j ACCEPT"

  # 5. Allow essential kernel-generated ICMP / ICMPv6 types
  if [ "$family" = "4" ]; then
    # Type 0: echo-reply, Type 3: destination-unreachable, Type 11: time-exceeded
    echo "-A PORTAL_EGRESS -p icmp --icmp-type 0 -j ACCEPT"
    echo "-A PORTAL_EGRESS -p icmp --icmp-type 3 -j ACCEPT"
    echo "-A PORTAL_EGRESS -p icmp --icmp-type 11 -j ACCEPT"
  else
    # Types 1-4: ICMPv6 error messages (destination unreachable, packet too big, time exceeded, parameter problem)
    echo "-A PORTAL_EGRESS -p ipv6-icmp --icmpv6-type 1 -j ACCEPT"
    echo "-A PORTAL_EGRESS -p ipv6-icmp --icmpv6-type 2 -j ACCEPT"
    echo "-A PORTAL_EGRESS -p ipv6-icmp --icmpv6-type 3 -j ACCEPT"
    echo "-A PORTAL_EGRESS -p ipv6-icmp --icmpv6-type 4 -j ACCEPT"
    # Types 133-137: Neighbor Discovery (RS, RA, NS, NA, redirect)
    echo "-A PORTAL_EGRESS -p ipv6-icmp --icmpv6-type 133 -j ACCEPT"
    echo "-A PORTAL_EGRESS -p ipv6-icmp --icmpv6-type 134 -j ACCEPT"
    echo "-A PORTAL_EGRESS -p ipv6-icmp --icmpv6-type 135 -j ACCEPT"
    echo "-A PORTAL_EGRESS -p ipv6-icmp --icmpv6-type 136 -j ACCEPT"
    echo "-A PORTAL_EGRESS -p ipv6-icmp --icmpv6-type 137 -j ACCEPT"
  fi

  # 6. Metadata server and link-local endpoints (placed after ND to avoid breaking neighbor discovery)
  if [ "${ALLOW_METADATA}" = "true" ]; then
    if [ "$family" = "4" ]; then
      echo "-A PORTAL_EGRESS -d 169.254.0.0/16 -j ACCEPT"
    else
      # AWS IMDS
      echo "-A PORTAL_EGRESS -d fd00:ec2::254/128 -j ACCEPT"
      # GCE metadata
      echo "-A PORTAL_EGRESS -d fd20:ce::254/128 -j ACCEPT"
      # IPv6 link-local (e.g. Azure WireServer fe80::1234:5678:9abc)
      echo "-A PORTAL_EGRESS -d fe80::/10 -j ACCEPT"
    fi
  else
    if [ "$family" = "4" ]; then
      echo "-A PORTAL_EGRESS -d 169.254.0.0/16 -j ${target}"
    else
      # AWS IMDS
      echo "-A PORTAL_EGRESS -d fd00:ec2::254/128 -j ${target}"
      # GCE metadata
      echo "-A PORTAL_EGRESS -d fd20:ce::254/128 -j ${target}"
      # IPv6 link-local
      echo "-A PORTAL_EGRESS -d fe80::/10 -j ${target}"
    fi
  fi

  # 7. Allow DNS requests to cluster DNS server IPs
  dns_ips=$(resolve_dns_ips)
  for ip in $(echo "${dns_ips}" | tr ',' ' '); do
    if [ -n "$ip" ]; then
      if [ "$family" = "4" ] && ! is_ipv6 "$ip"; then
        echo "-A PORTAL_EGRESS -d ${ip} -p udp --dport 53 -j ACCEPT"
        echo "-A PORTAL_EGRESS -d ${ip} -p tcp --dport 53 -j ACCEPT"
      elif [ "$family" = "6" ] && is_ipv6 "$ip"; then
        echo "-A PORTAL_EGRESS -d ${ip} -p udp --dport 53 -j ACCEPT"
        echo "-A PORTAL_EGRESS -d ${ip} -p tcp --dport 53 -j ACCEPT"
      fi
    fi
  done

  # 8. Allowed CIDRs
  for cidr in $(echo "${ALLOW_CIDRS}" | tr ',' ' '); do
    if [ -n "$cidr" ]; then
      if [ "$family" = "4" ] && ! is_ipv6 "$cidr"; then
        echo "-A PORTAL_EGRESS -d ${cidr} -j ACCEPT"
      elif [ "$family" = "6" ] && is_ipv6 "$cidr"; then
        echo "-A PORTAL_EGRESS -d ${cidr} -j ACCEPT"
      fi
    fi
  done

  # 9. Allowed TCP ports
  for port in $(echo "${ALLOW_PORTS}" | tr ',' ' '); do
    if [ -n "$port" ]; then
      echo "-A PORTAL_EGRESS -p tcp --dport ${port} -j ACCEPT"
    fi
  done

  # 10. Reject/drop remaining outbound ICMP from workload (e.g. echo-request)
  if [ "$family" = "4" ]; then
    echo "-A PORTAL_EGRESS -p icmp -j ${target}"
  else
    echo "-A PORTAL_EGRESS -p ipv6-icmp -j ${target}"
  fi

  # 11. Reject/drop all other outbound TCP and UDP traffic
  echo "-A PORTAL_EGRESS -p tcp -j ${target}"
  echo "-A PORTAL_EGRESS -p udp -j ${target}"
  echo "COMMIT"
}

apply_ipv6_rules() {
  if is_ipv6_disabled; then
    echo "IPv6 is disabled in this network namespace (${IPV6_DISABLE_PATH}=1); skipping ip6tables rules."
    return 0
  fi

  if [ "${TEST_FAIL_IP6TABLES}" = "true" ]; then
    echo "Simulating ip6tables failure for test (TEST_FAIL_IP6TABLES=true)" >&2
    if [ "${ALLOW_UNFILTERED_IPV6:-false}" = "true" ]; then
      echo "WARNING: ip6tables-restore failed, but ALLOW_UNFILTERED_IPV6=true is set. IPv6 egress will be UNFILTERED!" >&2
      return 0
    else
      echo "ERROR: Failed to apply ip6tables rules and IPv6 is enabled in this network namespace. Failing closed. Set ALLOW_UNFILTERED_IPV6=true to bypass." >&2
      return 1
    fi
  fi

  if ! command -v ip6tables-restore >/dev/null 2>&1; then
    if [ "${ALLOW_UNFILTERED_IPV6:-false}" = "true" ]; then
      echo "WARNING: ip6tables-restore not found, but ALLOW_UNFILTERED_IPV6=true is set. IPv6 egress will be UNFILTERED!" >&2
      return 0
    else
      echo "ERROR: ip6tables-restore not found and IPv6 is enabled in this network namespace. Failing closed. Set ALLOW_UNFILTERED_IPV6=true to bypass." >&2
      return 1
    fi
  fi

  rules_v6=$(generate_rules 6)
  if ! echo "$rules_v6" | ip6tables-restore; then
    if [ "${ALLOW_UNFILTERED_IPV6:-false}" = "true" ]; then
      echo "WARNING: ip6tables-restore failed, but ALLOW_UNFILTERED_IPV6=true is set. IPv6 egress will be UNFILTERED!" >&2
      return 0
    else
      echo "ERROR: Failed to apply ip6tables rules and IPv6 is enabled in this network namespace. Failing closed. Set ALLOW_UNFILTERED_IPV6=true to bypass." >&2
      return 1
    fi
  fi
}

case "${1:-}" in
  generate-rules|generate)
    generate_rules "${2:-4}"
    exit 0
    ;;
  --generate-iptables|-4)
    generate_rules 4
    exit 0
    ;;
  --generate-ip6tables|-6)
    generate_rules 6
    exit 0
    ;;
  apply-ipv6)
    apply_ipv6_rules
    exit $?
    ;;
  is-ipv6-disabled)
    if is_ipv6_disabled; then
      echo "disabled"
      exit 0
    else
      echo "enabled"
      exit 1
    fi
    ;;
esac

if [ -x /usr/local/bin/init-service-portals ]; then
  echo "Generating CA certificate in ${CA_DIR} and private cert/key in ${CA_PRIVATE_DIR} with chown ${CHOWN_UID}:${CHOWN_GID}..."
  /usr/local/bin/init-service-portals -cert-dir "${CA_DIR}" -key-dir "${CA_PRIVATE_DIR}" -chown-uid "${CHOWN_UID}" -chown-gid "${CHOWN_GID}"
fi

DNS_SERVER_IPS=$(resolve_dns_ips)
export DNS_SERVER_IPS

echo "Configuring iptables rules..."
echo "PROXY_PORT: ${PROXY_PORT}"
echo "PROXY_HTTPS_PORT: ${PROXY_HTTPS_PORT}"
echo "PROXY_UID: ${PROXY_UID}"
echo "INTERCEPT_PORTS: ${INTERCEPT_PORTS}"
echo "DNS_SERVER_IPS: ${DNS_SERVER_IPS}"
echo "ALLOW_METADATA: ${ALLOW_METADATA}"
echo "ALLOW_CIDRS: ${ALLOW_CIDRS}"
echo "ALLOW_PORTS: ${ALLOW_PORTS}"
echo "EGRESS_ACTION: ${EGRESS_ACTION}"
echo "ALLOW_UNFILTERED_IPV6: ${ALLOW_UNFILTERED_IPV6}"

rules_v4=$(generate_rules 4)
echo "$rules_v4" | iptables-restore

apply_ipv6_rules

echo "iptables rules configured successfully."

# Log the final ruleset
echo "=== iptables rules ==="
iptables-save
if ! is_ipv6_disabled && command -v ip6tables-save >/dev/null 2>&1; then
  echo "=== ip6tables rules ==="
  ip6tables-save 2>/dev/null || true
fi
