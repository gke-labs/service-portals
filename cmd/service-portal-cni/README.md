# service-portal-cni

`service-portal-cni` is a chained CNI plugin implementing the transparent interception mechanism for `service-portals` without requiring pod init containers or `CAP_NET_ADMIN` privileges in workload pods.

## How it Works

1. **Invocation**: Container runtimes (containerd/CRI-O) invoke `service-portal-cni` synchronously as part of the node's CNI configuration list (`/etc/cni/net.d/*.conflist`) during `CNI ADD` (pod sandbox creation).
2. **Pod Lookup**: Parses `K8S_POD_NAMESPACE` and `K8S_POD_NAME` from `CNI_ARGS`. Queries the Kubernetes API server using a node-scoped kubeconfig (`/etc/cni/net.d/service-portal.kubeconfig` or in-cluster credentials).
3. **Opt-in Match**: Checks if the pod has `portals.gke.io/intercept: "true"` or a `PortalPolicy` annotation. If not selected, it passes through `prevResult` unmodified.
4. **Network Configuration**: If selected, it enters the pod's network namespace (`CNI_NETNS`) via `nsenter` and installs:
   - NAT table DNAT rules redirecting target ports (e.g. 80, 443) to the node's DaemonSet proxy listener.
   - Filter table rules enforcing strictly default-deny egress:
     - Allows loopback and conntrack ESTABLISHED/RELATED
     - Allows cluster DNS resolution only
     - Allows TCP to the node proxy listener
     - Drops/rejects all other outbound TCP and UDP traffic.
5. **Fail-Closed Guarantee**: If the CNI plugin fails or is missing, CRI pod sandbox creation fails immediately with `FailedCreatePodSandBox`. Workload containers never start.
