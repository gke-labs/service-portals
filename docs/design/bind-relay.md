# Design proposal: a bind relay that node agents dial out to

**Status**: Proposal. Direction suggested by the maintainer (2026-11-16); nothing here is built.
**Date**: 2026-11-16
**Related**: [`egress-policy.md`](egress-policy.md), [`daemonset-mode.md`](daemonset-mode.md), the bind API (`pkg/portals/v1/bind.proto`), #277 (parked)

## Why

NRI mode now enforces only what was bound: an `EgressPolicy` and named secrets per pod UID, held by the node proxy and served over `PodBindService`. That service is reachable only on a Unix socket on the node. The component that should call it, the controller that creates sandboxes, runs elsewhere. The first user, gke-labs/eval-runner, is working around this with a ConfigMap of rules.

Three things are missing, and they are the same three whichever transport we pick:

1. **Reach.** A controller cannot call a node-local socket, and should not need to know which node a pod landed on.
2. **Durability.** Bindings live in the node proxy's memory. When it restarts, every sandbox on the node is denied until something binds it again.
3. **Ordering.** A pod is denied until bound, which is safe, but nothing tells the controller when it is safe to let the sandbox start.

#277 proposed a mutual-TLS listener on every node. It solves reach only, leaves node discovery to every caller, and adds an inbound listener to a host-network process on every node.

## Proposal

Add one small service, the **bind relay**. Node agents dial out to it and keep a connection open. Clients (sandbox controllers) connect to it and push policy and secrets for a pod UID. The relay forwards each push to the node that runs the pod. The node agent is where the state lives.

```
controller ──push(pod UID, policy / secrets, wait?)──▶ bind relay ◀──dials out── node agent (per node)
                                                          │  checks pod → node                │ holds policy + secrets,
                                                          │  against the Kubernetes API       │ persists them locally,
                                                          └────────── forwards ──────────────▶│ enforces them
```

### The node holds the state

The node agent is the source of truth for the pods on its node. It keeps policy and secrets in memory for enforcement, as today, and also writes them to a protected location on the node (see Security for where) so that a node proxy restart or update restores them without anyone re-pushing.

The relay is a router, not a store. It holds a push only until the node has accepted it, then forgets it. Consequences:

- Secrets are not concentrated. After delivery a secret exists only on the one node that needs it, as it does today.
- The relay can restart or be unavailable without affecting enforcement: nodes keep enforcing what they hold. Only pushes in flight are lost, and those callers see an error and retry.
- A node proxy restart no longer drops bindings.

### Flow

1. **Node connects.** The node agent dials the relay, authenticates as its node, and declares the pods it has (it already tracks them through NRI). It updates the declaration as pods come and go.
2. **Client pushes.** A client sends policy, or secrets, for a pod UID. These stay separate operations with the messages we already have (`PodPolicy`, `PodSecrets`); replacing secrets replaces the whole set, as today.
3. **Relay routes.** The relay looks the pod up in the Kubernetes API to find its node, and forwards the push only to the connection authenticated as that node. It does not use the node's own declaration to decide where secrets go (see Security).
4. **Node accepts.** The node agent validates the policy, stores and persists it, and acknowledges. The relay then drops its copy.
5. **Pod not there yet.** If the pod is not yet scheduled or the node has not declared it, the relay holds the push, in memory only, until the node declares the pod or a time limit expires. This covers a controller that pushes immediately after creating the pod, and bounds what is kept for a pod that never arrives.
6. **Pod removed.** The node agent deletes the pod's policy and secrets from memory and disk when the pod goes away. The relay drops anything pending for it.

### Waiting for acceptance

A push may ask to wait. The call then returns only when the node has accepted, or fails at the time limit. This is the signal a controller needs to hold a sandbox until its policy is in place.

**Accepted** means the node holds the policy and every secret that the policy names. A policy whose credential has not arrived is not accepted, so a sandbox is never released with a rule that will fail on its first request. A policy that names no secrets is accepted on its own.

## Security

- **Do not trust a node's claim about its pods.** If the relay sent a pod's secrets to whichever node declared that pod, a compromised node could claim any pod UID and collect its credentials. The relay routes by the pod's node as recorded in the Kubernetes API, and delivers only to the connection authenticated as that node. A node's declaration is used only to know when delivery can happen.
- **Nodes authenticate as a node.** The relay must be able to tie a connection to one node name. The mechanism is an open question below.
- **Clients are authorised.** Pushing policy and secrets for a pod is a privileged act. Clients authenticate, and an allowlist says who may push; an empty allowlist allows nobody. Whether authorisation is narrower than "may push for any pod" (per namespace, for example) is an open question.
- **Fail closed everywhere.** A pod with no accepted policy reaches nothing. A relay with no route to the node holds or fails the push; it never reports acceptance it did not get.
- **Secrets are never logged**, by the relay or the node, and the relay keeps them in memory only and only while a push is pending.
- **Where the node keeps them.** The node already holds every secret for its pods in memory, and root on the node can read them there, so writing them to a file does not widen who can obtain them at run time. The question is what survives which failure, and what is left at rest:

  | Where | Agent crash or container restart | Agent update (DaemonSet replaces the pod) | Node reboot | Left on persistent disk |
  |---|---|---|---|---|
  | Process memory (today) | lost | lost | lost | no |
  | Memory-backed `emptyDir` | kept | lost | lost | no |
  | `hostPath` on the node's memory-backed `/run` | kept | kept | lost | no |
  | `hostPath` on disk | kept | kept | kept | yes |

  A memory-backed filesystem belongs to the mount, not to the process, so a crash does not lose it. An `emptyDir` belongs to the pod, so an update, which replaces the pod, does lose it. A host path under `/run` belongs to the node and survives both.

  **Recommendation:** a host path under `/run`, beside the existing sockets in `/run/service-portal`, readable only by the proxy's user, outside any path a sandbox can mount, with a pod's entries removed when the pod goes away. It survives the two common cases (a crash and an update) and never writes a secret to persistent disk. A node reboot loses it; after a reboot the pods on that node have been restarted as well, are denied until bound again, and the controller pushes again as it would for a new pod. On start the node agent drops entries for pods that no longer exist.
- **Nothing new listens on the node.** Node agents only dial out.

## What changes for existing pieces

- `PodBindService` messages are reused for clients; the relay serves them, with the wait option added. The node-facing side is a new streaming service.
- The node proxy's Unix socket and `portal-nri-plugin bind-service` stay, for local debugging and for the e2e suite until it moves to the relay.
- #277 (inbound mutual-TLS listener on each node) is closed as not needed if this goes ahead.

## Alternatives

- **Per-node mutual-TLS listener (#277).** One flag on an existing binary, so it is the least work. It leaves node discovery, durability and ordering unsolved, and puts a listener on the node network.
- **Relay holds everything and re-pushes to nodes.** The first form of this idea. It makes node restarts trivial, but concentrates every sandbox's secrets in one service and makes that service's availability and restart everyone's problem. Holding state on the node keeps the relay small and the blast radius local.
- **Rules in a ConfigMap read by the node proxy.** What eval-runner is proposing as a stopgap. It cannot carry secrets, applies one policy to every pod, and brings back policy that is not attached to a pod by the component that created it.
- **Nodes pull per connection ("phone home").** Possible later with the same messages. It puts a round trip to a central service on the request path.

## Costs

- A new deployable, with its own upgrade and availability story.
- Several small PRs here instead of one, so it is slower to a first working version than #277.
- The relay needs read access to pods in the Kubernetes API.

## Open questions

1. **Node identity.** How does a node agent prove which node it is? Candidates are a projected service account token checked with TokenReview, if the token can be tied to the node the agent's pod runs on, or per-node client certificates. Not yet verified: whether bound service account tokens carry the node name on the Kubernetes versions we target.
2. **Node reboot.** With state under `/run`, a reboot loses bindings and the controller must push again. Is that acceptable, or do some users need bindings to survive a reboot, which means persistent disk and the at-rest exposure that comes with it?
3. **More than one relay replica.** A node is connected to one replica; a client may reach another. A single replica with leader election is the simple answer; routing between replicas is more work.
4. **Time limit for pending pushes.** How long the relay holds a push for a pod that has not arrived, and whether the client can set it.
5. **Client authorisation scope.** Any pod, or limited by namespace or by who created the pod.
6. **Relay restart.** Pending pushes are lost and waiting callers retry. Is that enough, or should the relay persist pending policy (never secrets)?

## Suggested order of work

Each step is one issue and one small PR:

1. Node agent keeps its `BindingStore` in a protected host path under `/run` and restores it on start; removes a pod's entries when the pod goes away. Useful on its own, with the existing socket.
2. Proto for the node-facing stream: declare pods, receive pushes, acknowledge.
3. Relay: accept node connections, route a push to a connected node, pending pushes with a time limit. In-process tests, no Kubernetes yet.
4. Relay checks pod to node against the Kubernetes API, and authenticates nodes.
5. Client-facing service on the relay, with authorisation and the wait option.
6. Node agent dials the relay; e2e binds through the relay.
7. Manifests and a migration note; close #277.
