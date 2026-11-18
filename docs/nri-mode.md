# Installing NRI Mode with Bound Egress Policy

In per-node NRI mode, `portal-node-agent` runs on each node as a DaemonSet to intercept container traffic via containerd's Node Resource Interface (NRI). Outbound egress from opted-in pods is denied by default until a sandbox controller binds an egress policy and companion secrets via `service-portal-controller`. Once bound, the node proxy swaps placeholder tokens for authentic credentials and enforces egress filtering.

For architectural background and protobuf definitions, see the [Service Portal Controller design](design/service-portal-controller.md) and [pkg/portals/v1/egress.proto](../pkg/portals/v1/egress.proto).

---

## 1. Node Prerequisites

Every node running the node agent requires:
- **Kubernetes 1.32+**: `TokenReview` must return the `authentication.kubernetes.io/node-name` claim for pod-bound projected tokens.
- **containerd with NRI enabled**:
  - containerd 2.0+: NRI is enabled by default (`disable = false` under `[plugins."io.containerd.nri.v1.nri"]`).
  - containerd 1.7+: Configure `disable = false` under `[plugins."io.containerd.nri.v1.nri"]` in `/etc/containerd/config.toml`.
- **NRI socket**: Active domain socket at `/var/run/nri/nri.sock`.
- **Privileged namespace**: `service-portal-system` labeled with `pod-security.kubernetes.io/enforce: privileged`.

### How to Check
Verify NRI is active on a node:
```bash
test -S /var/run/nri/nri.sock && echo "NRI is enabled"
```
**What you see**: `NRI is enabled`. If missing, update `/etc/containerd/config.toml` and run `systemctl restart containerd`.

---

## 2. Building or Obtaining Container Images

NRI mode requires three images built from the repository root:
1. `service-portal-controller`: Central gRPC controller (`images/service-portal-controller/Dockerfile`).
2. `service-portal-agent`: Node proxy engine (`images/service-portal-agent/Dockerfile`).
3. `service-portal-nri-plugin`: NRI lifecycle plugin and node init container (`images/service-portal-nri-plugin/Dockerfile`).

```bash
docker build -f images/service-portal-controller/Dockerfile -t <REG>/service-portal-controller:<TAG> .
docker build -f images/service-portal-agent/Dockerfile -t <REG>/service-portal-agent:<TAG> .
docker build -f images/service-portal-nri-plugin/Dockerfile -t <REG>/service-portal-nri-plugin:<TAG> .
```
Push all three images to a registry accessible by your cluster nodes.

---

## 3. Configuring Secrets and Applying Manifests

Deploy components in `service-portal-system`. The controller must be deployed before the node agent.

### Step 3a: Create Controller TLS Secrets
Create and label the namespace by hand before applying manifests so the Secrets can exist before the Deployment and DaemonSet are applied (both manifests also declare the namespace):
```bash
kubectl create namespace service-portal-system
kubectl label namespace service-portal-system pod-security.kubernetes.io/enforce=privileged

kubectl create secret tls service-portal-controller-tls -n service-portal-system \
  --cert=path/to/controller.crt --key=path/to/controller.key
kubectl create secret generic service-portal-controller-ca -n service-portal-system \
  --from-file=tls.crt=path/to/controller-ca.crt
```
*(The server certificate must include SAN `service-portal-controller.service-portal-system.svc`.)*

### Step 3b: Configure and Apply `k8s/controller.yaml`
In `k8s/controller.yaml`, configure:
- `image`: `<REG>/service-portal-controller:<TAG>`
- `--audience`: Expected TokenReview audience (e.g. `--audience=https://service-portal-controller`)
- `--node-agent-account`: `system:serviceaccount:service-portal-system:portal-node-agent`
- `--client-allowlist`: Permitted client service accounts (e.g. `system:serviceaccount:default:sandbox-controller`)

Apply: `kubectl apply -f k8s/controller.yaml`

### Step 3c: Configure and Apply `k8s/node-agent.yaml`
In `k8s/node-agent.yaml`, configure:
- Container images: `node-init` and `nri-plugin` to `<REG>/service-portal-nri-plugin:<TAG>`; `proxy` to `<REG>/service-portal-agent:<TAG>`
- `audience`: In volume `controller-token`, set `audience` to match `--audience` (e.g. `https://service-portal-controller`)

Apply: `kubectl apply -f k8s/node-agent.yaml`

---

## 4. Confirm Controller and Node Agents Are Healthy

Confirm Deployment and DaemonSet rollouts succeed:
```bash
kubectl rollout status deployment/service-portal-controller -n service-portal-system
kubectl rollout status daemonset/portal-node-agent -n service-portal-system
```
**What you see**: Both resources report successful rollout.

Confirm the node agent stream is connected:
```bash
kubectl logs -n service-portal-system -l app=service-portal-controller -c service-portal-controller
# Output contains: "stream connected"
kubectl logs -n service-portal-system -l app=portal-node-agent -c proxy
# Output contains: "controller: stream connected"
kubectl logs -n service-portal-system -l app=portal-node-agent -c nri-plugin
# Output contains registration with containerd /var/run/nri/nri.sock
```

### Real-Node Verification (Unprivileged DNS Port)
On real Linux nodes (e.g. GKE Standard with Container-Optimized OS or Ubuntu), the host network namespace enforces `net.ipv4.ip_unprivileged_port_start = 1024`. Because `proxy` runs as non-root (UID 65532) without added capabilities, verify that the proxy binds the unprivileged DNS port (`1053`) successfully:
1. Verify node unprivileged port threshold:
   ```bash
   sysctl net.ipv4.ip_unprivileged_port_start
   # Output: net.ipv4.ip_unprivileged_port_start = 1024
   ```
2. Verify `proxy` starts without permission errors:
   ```bash
   kubectl logs -n service-portal-system -l app=portal-node-agent -c proxy
   # Output contains: "Starting node DNS server on <nodeIP>:1053"
   ```
   Confirm no `bind: permission denied` errors appear.
3. Verify intercepted DNS reachability: Opted-in pod queries to port 53 (cluster DNS or external) are redirected by NRI netfilter rules to `<nodeIP>:1053` and answered by the proxy.

---

## 5. Opting In Workload Pods

A workload pod opts in to transparent interception with a single label:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: sandbox-workload
  labels:
    service-portal.gke.io/intercept: "true"
spec:
  containers:
  - name: workload
    image: alpine:latest
    command: ["sleep", "3600"]
```
NRI intercepts container creation, mounts the node CA at `/etc/service-portal/ca/tls.crt`, sets `SSL_CERT_FILE=/etc/service-portal/ca/tls.crt`, and installs host netfilter redirection.

### What You See Before Binding
Outbound traffic from an unbound opted-in pod fails closed. Because no policy rule exists for `httpbin.org`, DNS resolution fails:
```bash
kubectl exec sandbox-workload -- wget -T 5 -qO- http://httpbin.org/headers
```
**What you see**: `wget: bad address 'httpbin.org'`. Unlisted hostnames return `NXDOMAIN` at the node DNS proxy. See [What Happens to Unallowed Traffic](controller.md#what-happens-to-unallowed-traffic) for other protocols and port outcomes.

---

## 6. Node Readiness Taint Gate

To prevent opted-in pods from running unintercepted on nodes where the node agent is not yet ready:
1. Taint nodes: `kubectl taint nodes --all service-portal.gke.io/uninitialized:NoSchedule`
2. Opted-in pods do not tolerate the taint and stay `Pending`.
3. `portal-node-agent` specifies a matching toleration in `k8s/node-agent.yaml` (`service-portal.gke.io/uninitialized:NoSchedule`) and schedules.
4. Once the DaemonSet is `Ready`, remove the taint:
   ```bash
   kubectl taint nodes --all service-portal.gke.io/uninitialized-
   ```
**What you see**: The pending workload pod schedules, transitions to `Running`, and is intercepted by NRI.

---

## 7. Binding Policy and Injecting Secrets

Sandbox controllers call `PodBindService` on the controller to bind egress policy and inject credentials (see [docs/controller.md](controller.md) and [`pkg/controller/example_test.go`](../pkg/controller/example_test.go)).

Shortest complete policy (`policy.json`) and secrets (`secrets.json`):
```json
{"rules": [{"http": {"hostnames": ["httpbin.org"], "effects": {"replaceHeaders": [{"header": "Authorization", "prefix": "Bearer ", "credentialUri": "secret://api-token"}]}}}]}
```
```json
{"api-token": "secret-credential-value"}
```

To bind directly for manual testing via `service-portal-nri-plugin bind-service` on the node:
```bash
POD_UID=$(kubectl get pod sandbox-workload -o jsonpath='{.metadata.uid}')
kubectl exec -i -n service-portal-system daemonset/portal-node-agent -c nri-plugin -- \
  service-portal-nri-plugin bind-service bind --socket /run/service-portal/bind.sock --uid "$POD_UID" --policy-file - < policy.json
kubectl exec -i -n service-portal-system daemonset/portal-node-agent -c nri-plugin -- \
  service-portal-nri-plugin bind-service inject-secrets --socket /run/service-portal/bind.sock --uid "$POD_UID" --secrets-file - < secrets.json
```

### Verifying Swapped Credentials
Send a request containing a placeholder token to `httpbin.org`:
```bash
kubectl exec sandbox-workload -- wget -T 5 -qO- --header="Authorization: placeholder-token" http://httpbin.org/headers
```
**What you see**: The response echoes the headers received by `httpbin.org`:
```json
{
  "headers": {
    "Authorization": "Bearer secret-credential-value",
    "Host": "httpbin.org"
  }
}
```
The node proxy swapped the placeholder token for the authentic secret credential before forwarding the request upstream.

---

## 8. Troubleshooting and Lifecycle Behavior

### What to Check When Egress Is Denied
- **Node Agent Readiness**: Verify the pod is running on a node whose `portal-node-agent` is ready (`kubectl get pods -n service-portal-system -l app=portal-node-agent -o wide`).
- **Caller Attribution**: Check `kubectl logs -n service-portal-system -l app=portal-node-agent -c proxy` to confirm the caller IP was identified (`Caller: <namespace>/<pod>`). Untracked callers return HTTP 403 Forbidden.
- **Client Allowlist**: If binding via the controller returns `codes.PermissionDenied`, verify the client service account is included in `--client-allowlist`.

For response status meanings and destination traffic handling, see [docs/controller.md](controller.md#what-the-answers-mean) and [What Happens to Unallowed Traffic](controller.md#what-happens-to-unallowed-traffic).

### Agent Restart vs. Node Reboot
- **Node Agent Restart**: Bindings and secrets are stored in host tmpfs at `/run/service-portal/store`. They survive proxy container restarts, crashes, and DaemonSet upgrades without re-binding.
- **Node Reboot**: Host tmpfs is cleared on node reboot. All bindings and secrets are lost. The sandbox controller must re-push bindings for pods on that node.
