# Design proposal: adopt the Agent Substrate egress policy language

**Status**: Proposal. Direction agreed by the maintainer (2026-11-13) and revised after his review (2026-11-14). Nothing here is built.
**Date**: 2026-11-13
**Related**: [`daemonset-mode.md`](daemonset-mode.md), [`interception-mechanisms.md`](interception-mechanisms.md), the bind API (`pkg/portals/v1/bind.proto`)

## Why

Trying to use service-portals from another project showed that we have no configuration language. Today a rule is a `PortalRule` YAML document with a host, an inline token, a header name, a rewrite URL and a cache TTL. It has no default-deny, no wildcard or port matching, no stated precedence when rules overlap, and it puts the credential inside the rule, so every policy is a Secret and cannot be reviewed, diffed or shared.

Agent Substrate solves the same problem with the same threat model: an intercepting egress gateway that swaps placeholder credentials for real ones. Its `EgressPolicy` is better specified than anything we would write from scratch, and sharing a language means a policy written for one system is readable, and ideally usable, in the other.

## Decisions

1. **Adopt the Substrate egress language, copied into our tree.** We copy the `EgressRule` subtree from `agent-substrate/substrate`, file `api/ateapi/v1/ateapi.proto` (Apache 2.0, read at commit `cf5768a0`, 2026-11-13), into our own proto package. We do not import their module: the rules are embedded in a 3,268-line API whose top-level `EgressPolicy` depends on Substrate's actor and resource-metadata types, and parts of that file still carry alpha and preview markers.
2. **Stay wire-compatible.** Message names, field names and field numbers are kept exactly, and the copy records its source commit. Our own additions use field numbers from 1000 upward so they cannot collide with fields Substrate adds later.
3. **Replace only if present.** A credential header is replaced only when the request already carries that header; a request without it is forwarded unchanged. Today we set the header unconditionally. The Substrate behaviour is safer because a credential reaches only requests that ask for it.
4. **Hold `rewriteUrl` and `cacheTTL`.** Neither has a Substrate equivalent and neither is needed for the NRI mode. They are not carried into the new language now; if they return, they return as extensions.
5. **Policy is not secret.** The policy names secrets; it never contains them. Policy and secrets are injected separately over the bind API.
6. **One encoding.** A policy is a proto message: protojson wherever a person reads or writes it, binary proto on gRPC. No hand-written YAML schema and no second parser.

## The language we take

Copied messages: `EgressRule`, `HttpRule`, `HttpsRule`, `TlsPassthroughRule`, `Ports`, `AllPorts`, `HttpRuleEffects`, `CredentialHeader`, `ActorJwtSource`. We define our own small top-level `EgressPolicy` that holds `repeated EgressRule rules`, in place of Substrate's resource wrapper.

Semantics, taken as written in the Substrate file:

- **Rules are an unordered set of allows; anything unmatched is denied.**
- **Three protocols.** `http` is cleartext, decided per request on the authority. `https` is intercepted with the gateway CA, selected by SNI and then decided per request on the authority. `tls_passthrough` is forwarded undecrypted and decided once at the ClientHello.
- **Hostnames** are exact DNS names or a single leftmost `*` label. **Ports** are a list or all ports; `http` defaults to 80 and `https` to 443.
- **Precedence** when rules overlap: an exact hostname beats a wildcard, then a specific port beats all ports. Two rules that tie are rejected when the policy is loaded.
- **Effects** apply only from the deciding rule. The one effect is `replace_headers`: a header name, an optional prefix such as `"Bearer "`, and a credential source.

What we will not implement at first is rejected at load, so a policy never silently does less than it says: `tls_passthrough`, and the `actor_jwt` credential source (we do not mint identity tokens yet). Both stay in the schema.

## Policy and secrets: both injected over the bind API, separately

The policy and the secrets reach the proxy through the bind API, in separate calls, made by the controller that owns the sandbox before anything runs in it. The proxy reads neither from the Kubernetes API.

| Piece | Contains | How it reaches the proxy | Sensitivity |
| :--- | :--- | :--- | :--- |
| Policy | Hostnames, ports, header names, secret *names* | Bind call carrying an `EgressPolicy` | Not secret; safe to log, diff and review |
| Secrets | Name to token bytes | A separate bind-API call for the same pod | Secret; held in memory only, never logged |

A `CredentialHeader` refers to a secret **by name**, using Substrate's `credential_uri` field with our scheme `secret://<name>`. The name is resolved only against the secrets injected for that same pod.

**Why this shape: no confused deputy.** If the proxy fetched Kubernetes Secrets on a policy's say-so, a policy author could make the proxy, which has broad read access, hand over a secret the author is not entitled to. Here the proxy has no ambient access to any secret store. The caller of the bind API supplies the secrets itself, so it can only ever inject what it already holds, and a name in a policy can only reach a secret that the same caller put there.

Consequences:

- **A pod is denied until it is bound.** That is already how the node proxy treats an unbound pod, and it now also covers "no policy yet".
- **A missing name fails closed.** A policy that names a secret which has not been injected is accepted, but a request that needs it is refused with an error; the placeholder is never forwarded.
- **Secrets can be rotated without rebinding**, because they travel in their own call.
- **The bind API now carries secrets**, so its transport security matters more: the local Unix socket today, and mutual TLS for the controller-facing API.
- **Proxy restart loses bindings.** Policy and secrets live in memory, so after a node proxy restart pods are denied until the controller binds them again. This is fail-closed, and the controller needs a way to notice and re-bind.

## Example

Today, as a Secret:

```yaml
apiVersion: portals.gke.io/v1alpha1
kind: PortalRule
metadata: {name: github}
spec:
  host: api.github.com
  authHeader: Authorization
  authToken: ghp_real_token_here
```

Proposed. The policy, sent in the bind call (shown as protojson):

```json
{
  "rules": [
    {"https": {
      "hostnames": ["api.github.com"],
      "effects": {"replaceHeaders": [
        {"header": "Authorization", "prefix": "Bearer ",
         "credentialUri": "secret://github-token"}
      ]}
    }}
  ]
}
```

The secrets, sent in a separate call for the same pod: the name `github-token` and its token bytes.

Two visible differences for users: the `Bearer ` prefix is now explicit (today it is added implicitly when the header is `Authorization`), and the client must send an `Authorization` header with any placeholder value for the swap to happen. Injecting an auth header for GitHub is the canonical use case and the one the first implementation must serve.

## Trade-offs

**For**
- A specified language with default-deny, wildcards, ports and precedence, which we lack.
- Policies become reviewable, diffable and shareable; only token bytes are secret.
- One language across two projects that solve the same problem.
- The per-pod policy in the bind API becomes a typed message; today it is an opaque string.
- No confused-deputy risk: the proxy has no ambient access to secrets.

**Against**
- **A copy can drift.** Substrate's file is still changing. We track it by recorded commit and re-sync deliberately; the better long-term answer is for Substrate to publish the egress rules as a standalone module, which is worth asking for.
- **Behaviour change.** Replace-only-if-present breaks clients that send no placeholder header. It is the right default, and it needs a migration note.
- **Validation is ours to write.** Substrate expresses validation as comment tags processed by its own tooling. We copy the comments as documentation and implement the checks (hostname syntax, uniqueness, tie rejection) in Go.
- **Everything goes through the bind API.** There is no declarative path in which a user applies a ConfigMap and a Secret and is done; something must call bind for each pod. That suits sandboxes run by a controller, and is more work for a one-off pod.
- **Bindings are not durable.** They are lost when the node proxy restarts (see above).
- **Bounded DNS and wildcards.** Our DNS server answers only for policy hostnames. A wildcard rule means answering for any matching name, which needs upstream resolution for names we cannot enumerate.

## Settled in review (2026-11-14)

- **Credentials** are named secrets passed over the bind API; the proxy does not read Kubernetes Secrets.
- **Attachment** is the bind call, made before anything runs in the sandbox. Policy selection by pod annotation is not carried forward.
- **Proto location** is `pkg/portals/v1/egress.proto`, package `portals.v1`, with a header comment that links back to the Substrate file and commit it was copied from.
- **Attribution** waits for a use case. Our plain attribution headers are not carried into the new language, and `actor_jwt` stays in the schema but is rejected at load.

## Open questions

1. **Re-binding after a node proxy restart.** How does the controller learn that bindings were lost: a `Get` that reports unbound, a generation number, or a watch?
2. **One-off pods without a controller.** Is the `bind` subcommand on the node enough for now, or do we want a small declarative path later?

## Suggested order of work

Each step is one issue and one small PR:

1. Copy the proto, generate bindings, and load and validate a protojson policy, with tie rejection.
2. The matcher: protocol, hostname, port and precedence, with tests taken from the Substrate comments.
3. Bind API: the bind call carries an `EgressPolicy`, and a separate call injects named secrets for a pod.
4. Effects: replace-only-if-present, resolving `secret://<name>` against the pod's injected secrets.
5. Use the new policy in the node proxy and the NRI e2e suite; bounded DNS reads hostnames from it.
6. Remove `PortalRule` and annotation-based policy selection, with a migration note.

The bind API's server work should follow step 1, so its per-pod policy is typed from the start.
