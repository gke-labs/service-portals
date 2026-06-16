# Kellnr Caching Proxy & Private Registry on GKE - Terraform Deployment Lab

This folder contains the 100% codified, production-ready Terraform configuration for deploying Kellnr as a Cargo caching proxy and private registry on Google Kubernetes Engine (GKE) Autopilot.

This setup supports different scaling and performance options, making it ideal for GKE Lab environments, stress testing under concurrent workloads, or proof-of-concept deployments.

---

## 🏗️ Architecture Options

The deployment supports 6 distinct modes selectable via the `deployment_option` variable. These choices map automatically to CPU/Memory sizes, database tiers, and edge caching (CDN) configurations:

| Sizing & CDN Choice (`deployment_option`) | CDN Edge Cache | Storage Backend | GKE Replica Pods | Database Tier | Workload Purpose |
| :--- | :---: | :--- | :---: | :--- | :--- |
| **`gke_cdn_gcs`** (Default) | **Enabled** | GCS Bucket | 3 Pods (0.2 CPU) | `db-f1-micro` | Standard recommended public-facing caching proxy. |
| **`gke_cdn_filestore`** | **Enabled** | Filestore PVC | 3 Pods (0.2 CPU) | `db-f1-micro` | CDN option using shared file system rather than GCS. |
| **`gke_only_2node_gcs`** | Disabled | GCS Bucket | 22 Pods (4.0 CPU) | `db-n1-standard-16` | High-load internal stress test (scaled across 2 nodes). |
| **`gke_only_2node_filestore`** | Disabled | Filestore PVC | 22 Pods (4.0 CPU) | `db-n1-standard-16` | Dynamic shared filesystem load test. |
| **`gke_only_1node_gcs`** | Disabled | GCS Bucket | 11 Pods (4.0 CPU) | `db-n1-standard-16` | Medium-load internal stress test (contained on 1 node). |
| **`gke_only_1node_filestore`** | Disabled | Filestore PVC | 11 Pods (4.0 CPU) | `db-n1-standard-16` | Single-node dynamic NFS load test. |

---

## 📁 Repository Structure

The deployment is split into two phases to avoid plan-time validation errors with GKE custom resources (like GKE's `BackendConfig` and `Ingress` controllers) before the API server is live:

```
terraform/
├── README.md               # This deployment guide
├── infra/                  # Phase 1: GCP Infrastructure (VPC, SQL, GCS, GKE Cluster)
│   ├── database.tf
│   ├── filestore.tf
│   ├── gke.tf
│   ├── locals.tf
│   ├── outputs.tf
│   ├── providers.tf
│   ├── storage.tf
│   ├── variables.tf
│   └── vpc.tf
└── k8s/                    # Phase 2: Kubernetes Workloads (Deployments, Services, Ingress, Secrets)
    ├── k8s_resources.tf
    ├── locals.tf
    ├── outputs.tf
    ├── providers.tf
    └── variables.tf
```

---

## 🚀 Deployment Guide

### Prerequisites

1.  **GCP Identity Authentication**:
    Ensure the `google-cloud-cli` is installed and you have authenticated both the gcloud client and your Application Default Credentials (ADC):
    ```bash
    gcloud auth login
    gcloud auth application-default login
    ```
2.  **Target GCP Project & IAM Roles**:
    Identify your target GCP Project ID. The authenticated identity running the deployment must have the following IAM roles on the target project to create the VPC, GKE, databases, storage, and IAM bindings:
    *   `roles/owner` (or a combination of `roles/editor` and `roles/resourcemanager.projectIamAdmin`)
    *   *Note*: Creating Workload Identity bindings and service account IAM bindings requires project-level IAM administration write access.


---

### Step 1: Deploy Phase 1 (GCP Infrastructure)

1. Navigate to the `infra` directory:
   ```bash
   cd terraform/infra
   ```
2. Initialize Terraform:
   ```bash
   terraform init
   ```
3. Run `plan` to verify the resources to be created (replace `YOUR_PROJECT_ID` with your actual GCP Project):
   ```bash
   terraform plan -var="project_id=YOUR_PROJECT_ID" -var="deployment_option=gke_cdn_gcs"
   ```
4. Apply the configuration (this will provision the VPC, SQL Database, GCS Bucket, and GKE Autopilot cluster. This process takes **10-15 minutes**):
   ```bash
   terraform apply -var="project_id=YOUR_PROJECT_ID" -var="deployment_option=gke_cdn_gcs"
   ```

Upon completion, Terraform will write the details of the created resources to `terraform.tfstate`.

---

### Step 2: Deploy Phase 2 (Kubernetes Workloads)

1. Navigate to the `k8s` directory:
   ```bash
   cd ../k8s
   ```
2. Initialize the Kubernetes provider:
   ```bash
   terraform init
   ```
   *(This initializes the Kubernetes provider using the local state outputs exported from the `infra` directory).*
3. Deploy the Kellnr workloads:
   ```bash
   terraform apply
   ```

When the command completes, it will output the dynamic public Ingress Load Balancer IP address (if CDN was enabled).

---

## 🔍 Validation & Verification

### 1. Fetch the Database Connection Password
The SQL database password is dynamically generated at apply-time and stored securely inside a Kubernetes secret. You can retrieve it by running:
```bash
gcloud container clusters get-credentials kellnr-cluster --region us-central1 --project YOUR_PROJECT_ID
kubectl get secret kellnr-secrets -n kellnr -o jsonpath="{.data.db_password}" | base64 --decode
```

### 2. Verify Workload Pod Status
Check if the Kellnr pods are up and running:
```bash
kubectl get pods -n kellnr
```

### 3. Check CDN Ingress Status (GKE + CDN Option)
Retrieve the Ingress details to monitor the load balancer provisioning status:
```bash
kubectl get ingress kellnr-ingress -n kellnr
```
> [!NOTE]
> It can take 5-10 minutes for the GKE HTTP(S) Load Balancer and global IP bindings to fully propagate in GCP.

---

## 🗑️ Clean Up & Teardown

To completely clean up and delete all resources created in this lab, run the destroy commands in **reverse order**:

1. Destroy the Kubernetes workloads first:
   ```bash
   cd terraform/k8s
   terraform destroy
   ```
2. Destroy the GCP Infrastructure:
   ```bash
   cd ../infra
   terraform destroy -var="project_id=YOUR_PROJECT_ID" -var="deployment_option=gke_cdn_gcs"
   ```
