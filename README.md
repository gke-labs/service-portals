# service portals

Sevice Portals are simple HTTP/HTTPS proxy servers that run inside a kubernetes cluster, and make it easier to consume services that run outside the cluster.

## Components

### Service Portal
A reverse proxy that authenticates incoming requests and proxies them to a configured upstream service, injecting necessary authentication headers.

### Artifact Portal
A caching forward proxy designed to accelerate `pip` operations and other artifact downloads, especially during `docker build`.

## Accelerating `docker build`

The Artifact Portal can significantly speed up `pip install` operations in Docker builds by caching Python packages.

1.  **Start the Artifact Portal**:
    ```bash
    go run ./cmd/artifact-portal/main.go
    ```
    By default, it listens on `:8081` and caches to `/tmp/artifact-portal-cache`.

2.  **Use it in `docker build`**:
    You can pass the proxy settings as build arguments:
    ```bash
    docker build --build-arg http_proxy=http://<your-host-ip>:8081 \
                 --build-arg https_proxy=http://<your-host-ip>:8081 \
                 -t your-image .
    ```

    *Note: To enable caching for PyPI, you may need to use HTTP for the index and trust the hosts:*
    ```dockerfile
    RUN pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org \
                    -i http://pypi.org/simple -r requirements.txt
    ```

## Contributing

This project is licensed under the [Apache 2.0 License](LICENSE).

We welcome contributions! Please see [docs/contributing.md](docs/contributing.md) for more information.

We follow [Google's Open Source Community Guidelines](https://opensource.google.com/conduct/).

## Disclaimer

This is not an officially supported Google product.

This project is not eligible for the Google Open Source Software Vulnerability Rewards Program.
