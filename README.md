# Service Portals

Service Portals are simple HTTP/HTTPS proxy servers that run inside a Kubernetes cluster, and make it easier to consume services that run outside the cluster.

## Purpose

When running workloads in Kubernetes, consuming external APIs (like LLM services or GitHub) often requires managing API keys or tokens in each workload. Service Portals solve this problem by centralizing authentication and proxying requests. 

Instead of distributing API keys to every pod that needs to call an external service, you deploy a Service Portal in your cluster. The Service Portal is configured with the necessary credentials and acts as a transparent proxy. Internal workloads simply send requests to the in-cluster Service Portal (e.g., `http://gemini-portal`), and the portal securely forwards the request to the external API, injecting the required authentication headers.

## Available Portals

This repository provides specific portals for popular external services:

*   **Gemini Portal** (`gemini-portal/`): Proxies requests to Google's Generative Language API (`https://generativelanguage.googleapis.com`), automatically injecting the Gemini API key.
*   **Anthropic Portal** (`anthropic-portal/`): Proxies requests to the Anthropic API, injecting the necessary authentication.
*   **GitHub Portal** (`github-portal/`): Proxies requests to the GitHub API, handling GitHub authentication.

## Architecture

At the core is the **Service Portal Proxy** (`cmd/service-portal/`), a Go-based reverse proxy application. The individual portals build upon this core component to provide service-specific configurations and manifests.

Each portal typically includes:
*   A Go binary to run the proxy.
*   A Dockerfile to build the container image.
*   Kubernetes manifests (`k8s/manifests.yaml`) to deploy the portal as a Deployment and Service within your cluster.

## Contributing

This project is licensed under the [Apache 2.0 License](LICENSE).

We welcome contributions! Please see [docs/contributing.md](docs/contributing.md) for more information.

We follow [Google's Open Source Community Guidelines](https://opensource.google.com/conduct/).

## Disclaimer

This is not an officially supported Google product.

This project is not eligible for the Google Open Source Software Vulnerability Rewards Program.
