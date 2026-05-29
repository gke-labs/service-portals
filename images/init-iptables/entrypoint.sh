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

# Create a new chain
iptables -t nat -N PORTAL_OUTPUT || true

# Jump to PORTAL_OUTPUT from OUTPUT
iptables -t nat -A OUTPUT -p tcp -j PORTAL_OUTPUT

# Exclude loopback traffic
iptables -t nat -A PORTAL_OUTPUT -o lo -j RETURN

# Exclude traffic from our proxy user (to avoid infinite redirection loops)
iptables -t nat -A PORTAL_OUTPUT -m owner --uid-owner "${PROXY_UID}" -j RETURN

# Redirect specified TCP ports to the proxy
if [ "${INTERCEPT_PORTS}" = "*" ]; then
  iptables -t nat -A PORTAL_OUTPUT -p tcp -j REDIRECT --to-ports "${PROXY_PORT}"
else
  iptables -t nat -A PORTAL_OUTPUT -p tcp -m multiport --dports "${INTERCEPT_PORTS}" -j REDIRECT --to-ports "${PROXY_PORT}"
fi

echo "iptables rules configured successfully."
