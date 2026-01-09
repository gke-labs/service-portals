# Service Portals - Gemini Context

## Goal
Implement a simple HTTP/HTTPS proxy ("service-portal") in Go.
This proxy runs in K8s, authenticates incoming requests (conceptually, MVP might be simple), and proxies them to `https://generativelanguage.googleapis.com` injecting an upstream Authorization header.

## Plan
- [x] Initialize Go module
- [x] Implement `cmd/service-portal/main.go`
- [x] Create `images/service-portal/Dockerfile`
- [x] Create `dev/tasks/deploy-to-kube`
- [x] Create K8s manifests
- [ ] Create PR
