# Namespace for Kellnr deployment
resource "kubernetes_namespace" "kellnr" {
  metadata {
    name = "kellnr"
  }
}

# Kubernetes Service Account mapped to Google Service Account via Workload Identity
resource "kubernetes_service_account" "kellnr_ksa" {
  metadata {
    name      = "kellnr-ksa"
    namespace = kubernetes_namespace.kellnr.metadata[0].name
    annotations = {
      "iam.gke.io/gcp-service-account" = data.terraform_remote_state.infra.outputs.gsa_email
    }
  }
}

# Secrets store for DB connection password and GCS HMAC credentials
resource "kubernetes_secret" "kellnr_secrets" {
  metadata {
    name      = "kellnr-secrets"
    namespace = kubernetes_namespace.kellnr.metadata[0].name
  }

  type = "Opaque"

  data = {
    db_password         = data.terraform_remote_state.infra.outputs.db_password
    gcs_hmac_access_key = data.terraform_remote_state.infra.outputs.gcs_hmac_access_key_id
    gcs_hmac_secret_key = data.terraform_remote_state.infra.outputs.gcs_hmac_secret_key
  }
}

# Custom GKE BackendConfig CRD to enable CDN and Cloud Armor on the Load Balancer
resource "kubernetes_manifest" "kellnr_backend_config" {
  count = local.cfg.enable_cdn ? 1 : 0

  manifest = {
    apiVersion = "cloud.google.com/v1"
    kind       = "BackendConfig"
    metadata = {
      name      = "kellnr-backend-config"
      namespace = kubernetes_namespace.kellnr.metadata[0].name
    }
    spec = {
      cdn = {
        enabled      = true
        cacheMode    = "FORCE_CACHE_ALL"
        defaultTtl   = 300
        clientTtl    = 300
        cachePolicy = {
          includeHost        = true
          includeProtocol    = true
          includeQueryString = false
        }
      }
      securityPolicy = {
        name = data.terraform_remote_state.infra.outputs.cloud_armor_policy_name
      }
    }
  }
}

# Statically mapped PV referencing the pre-created Filestore instance in Phase 1
resource "kubernetes_persistent_volume" "filestore_pv" {
  count = local.cfg.storage_backend == "filestore" ? 1 : 0
  metadata {
    name = "kellnr-filestore-pv"
  }
  spec {
    capacity = {
      storage = "1Ti"
    }
    access_modes = ["ReadWriteMany"]
    persistent_volume_source {
      nfs {
        path   = "/vol1"
        server = data.terraform_remote_state.infra.outputs.kellnr_filestore_ip
      }
    }
    storage_class_name = "kellnr-filestore-static"
  }
}

# PVC bound to the static PersistentVolume
resource "kubernetes_persistent_volume_claim" "filestore_pvc" {
  count = local.cfg.storage_backend == "filestore" ? 1 : 0
  metadata {
    name      = "kellnr-storage-pvc"
    namespace = kubernetes_namespace.kellnr.metadata[0].name
  }
  spec {
    access_modes       = ["ReadWriteMany"]
    storage_class_name = "kellnr-filestore-static"
    volume_name        = kubernetes_persistent_volume.filestore_pv[0].metadata[0].name
    resources {
      requests = {
        storage = "1Ti"
      }
    }
  }
  wait_until_bound = false
}

# Kellnr Service (NodePort required for GKE Ingress integration)
resource "kubernetes_service" "kellnr_service" {
  metadata {
    name      = "kellnr-service"
    namespace = kubernetes_namespace.kellnr.metadata[0].name
    annotations = local.cfg.enable_cdn ? {
      "cloud.google.com/backend-config" = jsonencode({ "default" = "kellnr-backend-config" })
      "cloud.google.com/neg"            = jsonencode({ "ingress" = true })
    } : {}
  }
  spec {
    selector = {
      app = "kellnr"
    }
    port {
      port        = local.cfg.enable_cdn ? 80 : 8000
      target_port = 8000
      protocol    = "TCP"
    }
    type = "NodePort"
  }
}

# Kellnr Ingress (Global Load Balancer) - only deployed if CDN is enabled
resource "kubernetes_ingress_v1" "kellnr_ingress" {
  count = local.cfg.enable_cdn ? 1 : 0
  metadata {
    name      = "kellnr-ingress"
    namespace = kubernetes_namespace.kellnr.metadata[0].name
    labels = {
      "force-reconcile" = "1"
    }
    annotations = {
      "kubernetes.io/ingress.global-static-ip-name" = "kellnr-static-ip"
      "kubernetes.io/ingress.class"                 = "gce"
    }
  }
  spec {
    default_backend {
      service {
        name = kubernetes_service.kellnr_service.metadata[0].name
        port {
          number = 80
        }
      }
    }
  }
}

# Kellnr Core Workload Deployment
resource "kubernetes_deployment" "kellnr_deployment" {
  metadata {
    name      = "kellnr-deployment"
    namespace = kubernetes_namespace.kellnr.metadata[0].name
    labels = {
      app = "kellnr"
    }
  }
  spec {
    replicas = local.cfg.kellnr_replicas
    selector {
      match_labels = {
        app = "kellnr"
      }
    }
    template {
      metadata {
        labels = {
          app = "kellnr"
        }
      }
      spec {
        service_account_name = kubernetes_service_account.kellnr_ksa.metadata[0].name

        # 1. Kellnr Container
        container {
          name  = "kellnr"
          image = "ghcr.io/kellnr/kellnr:5"

          port {
            container_port = 8000
          }

          env {
            name  = "KELLNR_PROXY__ENABLED"
            value = "true"
          }

          env {
            name  = "KELLNR_OAUTH2__ENABLED"
            value = var.enable_oauth2 ? "true" : "false"
          }
          env {
            name  = "KELLNR_OAUTH2__ISSUER"
            value = var.kellnr_oauth2_issuer
          }
          env {
            name  = "KELLNR_OAUTH2__CLIENT_ID"
            value = var.kellnr_oauth2_client_id
          }
          env {
            name  = "KELLNR_OAUTH2__CLIENT_SECRET"
            value = var.kellnr_oauth2_client_secret
          }

          env {
            name  = "KELLNR_POSTGRESQL__ENABLED"
            value = "true"
          }
          env {
            name  = "KELLNR_POSTGRESQL__ADDRESS"
            value = "127.0.0.1"
          }
          env {
            name  = "KELLNR_POSTGRESQL__PORT"
            value = "5432"
          }
          env {
            name  = "KELLNR_POSTGRESQL__DB"
            value = data.terraform_remote_state.infra.outputs.db_name
          }
          env {
            name  = "KELLNR_POSTGRESQL__USER"
            value = data.terraform_remote_state.infra.outputs.db_user
          }
          env {
            name = "KELLNR_POSTGRESQL__PWD"
            value_from {
              secret_key_ref {
                name = kubernetes_secret.kellnr_secrets.metadata[0].name
                key  = "db_password"
              }
            }
          }

          env {
            name  = "KELLNR_ORIGIN__HOSTNAME"
            value = local.cfg.enable_cdn ? data.terraform_remote_state.infra.outputs.kellnr_static_ip_address : "kellnr-service.kellnr.svc.cluster.local"
          }
          env {
            name  = "KELLNR_ORIGIN__PORT"
            value = local.cfg.enable_cdn ? "80" : "8000"
          }
          env {
            name  = "KELLNR_ORIGIN__HTTPS"
            value = "false"
          }

          env {
            name  = "KELLNR_REGISTRY__DATA_DIR"
            value = "/data"
          }
          env {
            name  = "RUST_LOG"
            value = "debug,kellnr=debug"
          }

          # GCS bucket storage S3 compatible env injection
          dynamic "env" {
            for_each = local.cfg.storage_backend == "gcs" ? [1] : []
            content {
              name  = "KELLNR_STORAGE__TYPE"
              value = "s3"
            }
          }
          dynamic "env" {
            for_each = local.cfg.storage_backend == "gcs" ? [1] : []
            content {
              name  = "KELLNR_STORAGE__S3__BUCKET"
              value = data.terraform_remote_state.infra.outputs.gcs_bucket_name
            }
          }
          dynamic "env" {
            for_each = local.cfg.storage_backend == "gcs" ? [1] : []
            content {
              name = "KELLNR_STORAGE__S3__ACCESS_KEY"
              value_from {
                secret_key_ref {
                  name = kubernetes_secret.kellnr_secrets.metadata[0].name
                  key  = "gcs_hmac_access_key"
                }
              }
            }
          }
          dynamic "env" {
            for_each = local.cfg.storage_backend == "gcs" ? [1] : []
            content {
              name = "KELLNR_STORAGE__S3__SECRET_KEY"
              value_from {
                secret_key_ref {
                  name = kubernetes_secret.kellnr_secrets.metadata[0].name
                  key  = "gcs_hmac_secret_key"
                }
              }
            }
          }
          dynamic "env" {
            for_each = local.cfg.storage_backend == "gcs" ? [1] : []
            content {
              name  = "KELLNR_STORAGE__S3__ENDPOINT"
              value = "https://storage.googleapis.com"
            }
          }
          dynamic "env" {
            for_each = local.cfg.storage_backend == "gcs" ? [1] : []
            content {
              name  = "KELLNR_STORAGE__S3__REGION"
              value = data.terraform_remote_state.infra.outputs.region
            }
          }

          volume_mount {
            name       = "kellnr-storage-volume"
            mount_path = "/data"
          }

          resources {
            limits = {
              cpu    = "1"
              memory = "2Gi"
            }
            requests = {
              cpu    = local.cfg.kellnr_cpu
              memory = local.cfg.kellnr_memory
            }
          }
        }

        # 2. Cloud SQL Proxy Sidecar
        container {
          name  = "cloud-sql-proxy"
          image = "gcr.io/cloud-sql-connectors/cloud-sql-proxy:2.1.0"
          args = [
            data.terraform_remote_state.infra.outputs.db_connection_name,
            "--port=5432"
          ]
          security_context {
            run_as_non_root = true
          }
          resources {
            limits = {
              cpu    = "500m"
              memory = "512Mi"
            }
            requests = {
              cpu    = "100m"
              memory = "128Mi"
            }
          }
        }

        # Mount dynamic volume backing (PVC or emptyDir)
        volume {
          name = "kellnr-storage-volume"

          dynamic "persistent_volume_claim" {
            for_each = local.cfg.storage_backend == "filestore" ? [1] : []
            content {
              claim_name = kubernetes_persistent_volume_claim.filestore_pvc[0].metadata[0].name
            }
          }

          dynamic "empty_dir" {
            for_each = local.cfg.storage_backend == "gcs" ? [1] : []
            content {}
          }
        }
      }
    }
  }
}
