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
PROXY_UID=${PROXY_UID:-1337}
INTERCEPT_PORTS=${INTERCEPT_PORTS:-80}

echo "Configuring iptables rules..."
echo "PROXY_PORT: ${PROXY_PORT}"
echo "PROXY_UID: ${PROXY_UID}"
echo "INTERCEPT_PORTS: ${INTERCEPT_PORTS}"

# ==================== NAT Redirection ====================

# Create a new NAT chain
iptables -t nat -N PORTAL_OUTPUT || true

# Jump to PORTAL_OUTPUT from OUTPUT
iptables -t nat -A OUTPUT -p tcp -j PORTAL_OUTPUT

# Exclude loopback traffic from redirection
iptables -t nat -A PORTAL_OUTPUT -o lo -j RETURN

# Exclude traffic from our proxy user to prevent infinite redirection loops
iptables -t nat -A PORTAL_OUTPUT -m owner --uid-owner "${PROXY_UID}" -j RETURN

# Redirect specified TCP ports to the proxy
if [ "${INTERCEPT_PORTS}" = "*" ]; then
  iptables -t nat -A PORTAL_OUTPUT -p tcp -j REDIRECT --to-ports "${PROXY_PORT}"
else
  iptables -t nat -A PORTAL_OUTPUT -p tcp -m multiport --dports "${INTERCEPT_PORTS}" -j REDIRECT --to-ports "${PROXY_PORT}"
fi

# ==================== Egress Filtering (No Bypass) ====================

# 1. Allow all loopback traffic
iptables -A OUTPUT -o lo -j ACCEPT

# 2. Allow all traffic to localhost (127.0.0.1) and the proxy port.
# This is crucial for locally-generated redirected packets to bypass the egress filter block.
iptables -A OUTPUT -d 127.0.0.1 -j ACCEPT
iptables -A OUTPUT -p tcp --dport "${PROXY_PORT}" -j ACCEPT

# 3. Allow established and related connections (essential for inbound probes and active connections)
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# 4. Allow all outbound traffic originating from our proxy user (UID 1337) to the external network
iptables -A OUTPUT -m owner --uid-owner "${PROXY_UID}" -j ACCEPT

# 5. Allow DNS requests (UDP and TCP on port 53) so the workload can resolve hostnames
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

# 6. Reject/drop all other outbound TCP and UDP traffic from the pod to external networks.
# This prevents workload processes from bypassing the proxy by using unauthorized ports or connecting directly.
iptables -A OUTPUT -p tcp -j REJECT --reject-with icmp-port-unreachable
iptables -A OUTPUT -p udp -j REJECT --reject-with icmp-port-unreachable

echo "iptables rules configured successfully."
