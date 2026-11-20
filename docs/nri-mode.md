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

## Deployment Path: `ap deploy` vs. `kubectl apply`

Choose your deployment method before proceeding:
- **With `ap deploy` (recommended)**: Section 2 is not needed. `ap deploy` automatically builds the container images referenced by the manifests, pushes them using `IMAGE_PREFIX` (or loads them directly when targeting a local `kind` cluster), and applies the manifests unchanged to your active Kubernetes cluster context. Proceed directly to [Section 3](#3-configuring-secrets-and-applying-manifests).
- **With plain `kubectl apply`**: Follow [Section 2](#2-building-or-obtaining-container-images-plain-kubectl-apply-only) to build and push images with Docker, set the container `image` fields in both manifests to your published tags, and then proceed to Section 3.

---

## 2. Building or Obtaining Container Images (Plain `kubectl apply` only)

When deploying with plain `kubectl apply`, build the three required images from the repository root:
1. `service-portal-controller`: Central gRPC controller (`images/service-portal-controller/Dockerfile`).
2. `service-portal-agent`: Node proxy engine (`images/service-portal-agent/Dockerfile`).
3. `service-portal-nri-plugin`: NRI lifecycle plugin and node init container (`images/service-portal-nri-plugin/Dockerfile`).

```bash
docker build -f images/service-portal-controller/Dockerfile -t <REG>/service-portal-controller:<TAG> .
docker build -f images/service-portal-agent/Dockerfile -t <REG>/service-portal-agent:<TAG> .
docker build -f images/service-portal-nri-plugin/Dockerfile -t <REG>/service-portal-nri-plugin:<TAG> .
```
Push all three images to a registry accessible by your cluster nodes, and set the container `image` fields in `k8s/controller.yaml` and `k8s/node-agent.yaml` to point to your published images.

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

### Step 3b: Configure the Controller
Create the `service-portal-config` ConfigMap using `dev/tasks/configure`, specifying the client allowlist:
```bash
dev/tasks/configure --client-allowlist="system:serviceaccount:default:sandbox-controller"
```
The token audience defaults to the fixed value `https://service-portal-controller`, matching the projected token audience in `k8s/node-agent.yaml`. The node agent account defaults to `system:serviceaccount:service-portal-system:portal-node-agent`, matching `k8s/node-agent.yaml`.

Configuration comes before applying manifests because `ap deploy` waits for applied workloads to become ready. (With a plain `kubectl apply`, applying manifests before configuring causes the controller Deployment to sit in `CreateContainerConfigError` until `dev/tasks/configure` is run.)

### Step 3c: Apply Manifests
Apply both `k8s/controller.yaml` and `k8s/node-agent.yaml`:

- **Using `ap deploy` (recommended)**: Apply both manifests unchanged; `ap deploy` builds the images, applies the manifests directly to your active cluster, and waits for workloads to become ready:
  ```bash
  ap deploy k8s/controller.yaml k8s/node-agent.yaml
  ```
  *(If pushing to a remote registry, set `IMAGE_PREFIX=<REG>`, e.g. `IMAGE_PREFIX=gcr.io/my-project ap deploy k8s/controller.yaml k8s/node-agent.yaml`.)*

- **Using `kubectl apply`**: After setting the container `image` fields in both manifests to your published images from Section 2, apply both manifests:
  ```bash
  kubectl apply -f k8s/controller.yaml -f k8s/node-agent.yaml
  ```

### Step 3d: Trust Private Upstream CAs (Optional)
If in-cluster services or internal API gateways use TLS certificates issued by a private Certificate Authority, you can configure the node agent's proxy to trust that CA without modifying the manifests.

Supply a PEM certificate bundle in a ConfigMap named `service-portal-upstream-ca` in the `service-portal-system` namespace. You can pass `--upstream-ca-file` to `dev/tasks/configure` or create the ConfigMap directly with `kubectl`:
```bash
# Via dev/tasks/configure (restarts the DaemonSet automatically if already running):
dev/tasks/configure --client-allowlist="system:serviceaccount:default:sandbox-controller" \
  --upstream-ca-file=path/to/upstream-ca.crt

# Or directly via kubectl:
kubectl create configmap service-portal-upstream-ca -n service-portal-system \
  --from-file=tls.crt=path/to/upstream-ca.crt
```
The node agent mounts this ConfigMap optionally and adds the certificates to the system root pool. Public upstreams continue to verify against system roots alongside your private CA. If no ConfigMap is created, the node agent verifies upstream TLS against the system root pool only.

The CA bundle is read once at proxy startup. If the node agent DaemonSet is already running when the ConfigMap is created or updated, restart it to load the bundle:
```bash
kubectl rollout restart daemonset/portal-node-agent -n service-portal-system
kubectl rollout status daemonset/portal-node-agent -n service-portal-system
```

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
Outbound traffic from an unbound opted-in pod fails closed by silence rather than refusal: until an egress policy is bound, the node agent drops outbound traffic. Similarly, DNS queries whose source address the node agent cannot yet map to a pod (unknown callers) are dropped without an answer rather than returning an immediate `NXDOMAIN`, preventing negative answer caching during pod startup. DNS queries get no answer (UDP) or are held (TCP), and proxied connections from unbound pods get no response (not `NXDOMAIN`, not `403 Access Denied`, and not a TCP reset). (Note that HTTP and TLS requests from an unknown caller are actively denied with HTTP `403 Forbidden` or TLS termination).

This appears to client workloads as packet loss, so standard network timeouts and retry logic apply automatically (e.g., in init containers running `git clone` or package managers) without terminating early on a negative answer or caching a negative DNS lookup:
```bash
kubectl exec sandbox-workload -- wget -T 5 -qO- http://httpbin.org/headers
```
**What you see**: `wget: download timed out`. The request times out because the node agent drops traffic from unbound pods until a policy is bound. Once a policy is bound via the controller, new requests and retries flow according to that policy without restarting the pod.

Workloads should therefore retry network calls rather than failing fast on the initial attempt.

In contrast, once a policy is bound, requests for unlisted hostnames outside that policy are actively refused with `NXDOMAIN` for DNS or HTTP `403 Forbidden` at the proxy. See [What Happens to Unallowed Traffic](controller.md#what-happens-to-unallowed-traffic) for post-binding protocol and port outcomes.

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
