# Cargo Caching Proxy & Private Registry Portal (Kellnr)

This portal deploys **Kellnr** inside a GKE cluster to act as a secure, caching proxy for crates.io and a private registry for Rust Cargo clients.

It accelerates Rust container builds and dynamic builder workloads, and satisfies security requirements for private node networks.

---

## 📖 Architecture & Features

*   **Smart Egress Control**: Allows workloads to pull public Rust dependencies without GKE nodes needing public IP addresses or direct external egress.
*   **Edge Caching (Cloud CDN)**: Serves cached package binaries (`.crate` files) and sparse registry indexes from the Google Edge. This provides sub-10ms response times for cached packages and completely bypasses GKE network egress limits.
*   **Workload Identity Security**: Securely connects to GCP resources (Cloud SQL, Cloud Storage) using GKE Workload Identity without hardcoding GCP JSON keys.
*   **OIDC Federation**: Optionally integrates with Google OIDC provider to authenticate Rust developers or CI/CD runners before allowing access to private crates.

---

## 🚀 Deployment Options

### Option A: Complete Automated Deployment (Terraform)
We provide a **two-phase Terraform package** that handles the complete provisioning of both GCP cloud infrastructure (VPC, NAT, GKE Autopilot, Cloud SQL, GCS Bucket, Cloud Armor) and the GKE resources.

For detailed steps, follow the [Terraform Deployment Lab Guide](terraform/README.md).

---

### Option B: Manual Workload Deployment (Existing GKE Cluster)
If you already have a GKE cluster running with a Cloud SQL PostgreSQL database, you can deploy the workloads manually:

1.  **Configure GCP Infrastructure**:
    *   Create a Google Service Account (GSA) `kellnr-gsa` and grant it the `roles/cloudsql.client` and `roles/storage.objectAdmin` roles.
    *   Create a GCS Bucket for crate storage (e.g., `kellnr-crates-YOUR_PROJECT_ID`). Generate an HMAC key for `kellnr-gsa` on this bucket.
    *   Enable GKE Workload Identity binding between `kellnr-gsa` and the GKE KSA `kellnr-ksa` in GKE namespace `kellnr`.
    *   Create a global static IP named `kellnr-static-ip`.

2.  **Create Kubernetes Secrets**:
    Create the namespace and secrets containing database connection passwords and HMAC credentials:
    ```bash
    kubectl create namespace kellnr
    
    kubectl create secret generic kellnr-secrets -n kellnr \
      --from-literal=db_password="YOUR_DATABASE_PASSWORD" \
      --from-literal=gcs_hmac_access_key="YOUR_HMAC_ACCESS_KEY_ID" \
      --from-literal=gcs_hmac_secret_key="YOUR_HMAC_SECRET_KEY"
    ```

3.  **Apply Manifests**:
    *   Open [k8s/manifests.yaml](k8s/manifests.yaml) and replace all instances of `YOUR_PROJECT_ID` and `YOUR_LB_IP_OR_STATIC_IP` with your actual values.
    *   Apply the manifest:
        ```bash
        kubectl apply -f k8s/manifests.yaml
        ```

---

## ⚙️ Cargo Client Configuration

To configure your local Cargo client or CI/CD runner to fetch dependencies from the caching proxy:

1. Retrieve the public Load Balancer IP address (if CDN is enabled):
   ```bash
   kubectl get ingress kellnr-ingress -n kellnr
   ```
2. Create or edit your client's `~/.cargo/config.toml` file to redirect crates.io requests:
   ```toml
   [registries.crates-io]
   protocol = "sparse"
   registry = "sparse+http://<INGRESS_IP_OR_STATIC_IP>/api/v1/cratesio/"
   ```
   *(Cargo will now automatically check the proxy for warm cache hits before pulling from crates.io).*
