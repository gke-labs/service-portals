# Service Portals

Service Portals are simple HTTP/HTTPS proxy servers designed to run within a Kubernetes cluster. Their primary purpose is to simplify the consumption of external services (running outside the cluster) by internal workloads.

## Architecture

The project consists of the following components:

- **Service Portal Proxy**: A Go-based reverse proxy application.
    - Source: `cmd/service-portal/`
    - Functionality: Authenticates incoming requests and proxies them to a configured upstream service (e.g., `https://generativelanguage.googleapis.com`), injecting necessary authentication headers (e.g., API keys).

- **Artifact Portal Proxy**: A Go-based caching forward proxy.
    - Source: `cmd/artifact-portal/`
    - Functionality: Caches artifact downloads (like Python wheels) to speed up repeated operations, especially in CI/CD and Docker builds.
    - Shared logic: Uses `pkg/proxy/` for common proxying functionality.

- **Deployment**:
    - Dockerfile: `images/service-portal/Dockerfile`
    - Kubernetes Manifests: `k8s/manifests.yaml` (Deployment and Service definitions)

## Development

- **Build & Deploy**: Helper scripts are located in `dev/tasks/`.
- **Conventions**:
    - Go modules for dependency management.
    - Standard Kubernetes resource definitions.