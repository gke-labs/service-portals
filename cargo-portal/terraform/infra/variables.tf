variable "project_id" {
  type        = string
  description = "The GCP project ID to deploy resources to."
}

variable "region" {
  type        = string
  default     = "us-central1"
  description = "The GCP region to deploy resources to."
}

variable "zone" {
  type        = string
  default     = "us-central1-a"
  description = "The GCP zone to deploy zonal resources (like Filestore)."
}

variable "deployment_option" {
  type        = string
  default     = "gke_cdn_gcs"
  description = "The deployment option to run: gke_cdn_gcs, gke_cdn_filestore, gke_only_2node_gcs, gke_only_2node_filestore, gke_only_1node_gcs, gke_only_1node_filestore"

  validation {
    condition     = contains(["gke_cdn_gcs", "gke_cdn_filestore", "gke_only_2node_gcs", "gke_only_2node_filestore", "gke_only_1node_gcs", "gke_only_1node_filestore"], var.deployment_option)
    error_message = "Deployment option must be one of: gke_cdn_gcs, gke_cdn_filestore, gke_only_2node_gcs, gke_only_2node_filestore, gke_only_1node_gcs, gke_only_1node_filestore."
  }
}

variable "allowed_ip_ranges" {
  type        = list(string)
  default     = []
  description = "IP ranges allowed to access the Ingress. Used by Cloud Armor. Set to specific corporate ranges to restrict access."
}
