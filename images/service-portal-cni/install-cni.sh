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

CNI_BIN_DIR=${CNI_BIN_DIR:-/host/opt/cni/bin}
CNI_NET_DIR=${CNI_NET_DIR:-/host/etc/cni/net.d}
KUBECONFIG_TARGET="${CNI_NET_DIR}/service-portal.kubeconfig"

echo "Installing service-portal-cni binary to ${CNI_BIN_DIR}..."
mkdir -p "${CNI_BIN_DIR}"
cp -f /usr/local/bin/service-portal-cni "${CNI_BIN_DIR}/service-portal-cni"
chmod 755 "${CNI_BIN_DIR}/service-portal-cni"

echo "Writing node-scoped kubeconfig to ${KUBECONFIG_TARGET}..."
mkdir -p "${CNI_NET_DIR}"

# If serviceaccount credentials exist, generate kubeconfig pointing to Kubernetes API server
if [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
    TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
    CA_DATA=$(base64 /var/run/secrets/kubernetes.io/serviceaccount/ca.crt | tr -d '\r\n')
    API_SERVER="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}"
    
    cat <<EOF > "${KUBECONFIG_TARGET}"
apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: ${CA_DATA}
    server: ${API_SERVER}
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: service-portal-cni
  name: service-portal-cni
current-context: service-portal-cni
users:
- name: service-portal-cni
  user:
    token: ${TOKEN}
EOF
elif [ -f /etc/kubernetes/kubelet.conf ]; then
    cp -f /etc/kubernetes/kubelet.conf "${KUBECONFIG_TARGET}"
else
    # Fallback default for kind
    cat <<EOF > "${KUBECONFIG_TARGET}"
apiVersion: v1
kind: Config
clusters:
- cluster:
    insecure-skip-tls-verify: true
    server: https://127.0.0.1:6443
  name: kind
contexts:
- context:
    cluster: kind
    user: default
  name: default
current-context: default
users:
- name: default
  user:
    token: ""
EOF
fi
chmod 600 "${KUBECONFIG_TARGET}"

echo "Patching CNI conflist in ${CNI_NET_DIR}..."
# Find first conflist file
CONFLIST=$(find "${CNI_NET_DIR}" -maxdepth 1 -name "*.conflist" | head -n 1)

if [ -z "${CONFLIST}" ]; then
    echo "Warning: no .conflist file found in ${CNI_NET_DIR}. Will wait for one..."
    while [ -z "${CONFLIST}" ]; do
        sleep 2
        CONFLIST=$(find "${CNI_NET_DIR}" -maxdepth 1 -name "*.conflist" | head -n 1)
    done
fi

echo "Found conflist: ${CONFLIST}"

if jq -e '.plugins[] | select(.type == "service-portal-cni")' "${CONFLIST}" >/dev/null 2>&1; then
    echo "service-portal-cni is already in ${CONFLIST}"
else
    echo "Appending service-portal-cni plugin to ${CONFLIST}..."
    TMP_FILE="${CONFLIST}.tmp.$$"
    jq '.plugins += [{
        "type": "service-portal-cni",
        "kubeconfig": "/etc/cni/net.d/service-portal.kubeconfig",
        "proxyPort": 8080,
        "proxyHttpsPort": 8443,
        "interceptPorts": "80,443"
    }]' "${CONFLIST}" > "${TMP_FILE}"
    mv "${TMP_FILE}" "${CONFLIST}"
    echo "Successfully chained service-portal-cni into ${CONFLIST}"
fi

echo "service-portal-cni installation complete."

if [ "${SLEEP_FOREVER:-false}" = "true" ]; then
    echo "Sleeping forever as requested..."
    exec sleep infinity
fi

exit 0
