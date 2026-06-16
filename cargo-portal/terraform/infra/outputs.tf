output "project_id" {
  value = var.project_id
}

output "region" {
  value = var.region
}

output "gke_cluster_name" {
  value = google_container_cluster.primary.name
}

output "gke_cluster_endpoint" {
  value = google_container_cluster.primary.endpoint
}

output "gke_cluster_ca_certificate" {
  value = google_container_cluster.primary.master_auth[0].cluster_ca_certificate
}

output "gsa_email" {
  value = google_service_account.kellnr_gsa.email
}

output "db_connection_name" {
  value = "${var.project_id}:${var.region}:${google_sql_database_instance.kellnr_postgres.name}"
}

output "db_name" {
  value = google_sql_database.kellnr_db.name
}

output "db_user" {
  value = google_sql_user.kellnr_user.name
}

output "db_password" {
  value     = random_password.db_password.result
  sensitive = true
}

output "gcs_bucket_name" {
  value = local.cfg.storage_backend == "gcs" ? google_storage_bucket.kellnr_bucket[0].name : ""
}

output "gcs_hmac_access_key_id" {
  value = local.cfg.storage_backend == "gcs" ? google_storage_hmac_key.kellnr_hmac_key[0].id : ""
}

output "gcs_hmac_secret_key" {
  value     = local.cfg.storage_backend == "gcs" ? google_storage_hmac_key.kellnr_hmac_key[0].secret : ""
  sensitive = true
}

output "kellnr_static_ip_address" {
  value = local.cfg.enable_cdn ? google_compute_global_address.kellnr_static_ip[0].address : ""
}

output "cloud_armor_policy_name" {
  value = local.cfg.enable_cdn ? google_compute_security_policy.cloud_armor_policy[0].name : ""
}

output "cfg" {
  value = local.cfg
}

output "kellnr_network_name" {
  value = google_compute_network.kellnr_network.name
}

output "kellnr_filestore_ip" {
  value = local.cfg.storage_backend == "filestore" ? google_filestore_instance.kellnr_filestore[0].networks[0].ip_addresses[0] : ""
}
