locals {
  options = {
    gke_cdn_gcs = {
      enable_cdn        = true
      storage_backend   = "gcs"
      database_tier     = "db-f1-micro"
      kellnr_replicas   = 3
      kellnr_cpu        = "200m"
      kellnr_memory     = "512Mi"
    }
    gke_cdn_filestore = {
      enable_cdn        = true
      storage_backend   = "filestore"
      database_tier     = "db-f1-micro"
      kellnr_replicas   = 3
      kellnr_cpu        = "200m"
      kellnr_memory     = "512Mi"
    }
    gke_only_2node_gcs = {
      enable_cdn        = false
      storage_backend   = "gcs"
      database_tier     = "db-n1-standard-16"
      kellnr_replicas   = 22
      kellnr_cpu        = "4"
      kellnr_memory     = "8Gi"
    }
    gke_only_2node_filestore = {
      enable_cdn        = false
      storage_backend   = "filestore"
      database_tier     = "db-n1-standard-16"
      kellnr_replicas   = 22
      kellnr_cpu        = "4"
      kellnr_memory     = "8Gi"
    }
    gke_only_1node_gcs = {
      enable_cdn        = false
      storage_backend   = "gcs"
      database_tier     = "db-n1-standard-16"
      kellnr_replicas   = 11
      kellnr_cpu        = "4"
      kellnr_memory     = "8Gi"
    }
    gke_only_1node_filestore = {
      enable_cdn        = false
      storage_backend   = "filestore"
      database_tier     = "db-n1-standard-16"
      kellnr_replicas   = 11
      kellnr_cpu        = "4"
      kellnr_memory     = "8Gi"
    }
  }

  cfg = local.options[var.deployment_option]
}
