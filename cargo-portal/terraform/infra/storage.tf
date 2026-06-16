resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "google_storage_bucket" "kellnr_bucket" {
  count         = local.cfg.storage_backend == "gcs" ? 1 : 0
  name          = "kellnr-crates-${var.project_id}-${random_id.bucket_suffix.hex}"
  location      = var.region
  force_destroy = true # Allow cleanup of all storage objects on destroy

  public_access_prevention = "enforced"
}

resource "google_storage_hmac_key" "kellnr_hmac_key" {
  count                 = local.cfg.storage_backend == "gcs" ? 1 : 0
  service_account_email = google_service_account.kellnr_gsa.email
  project               = var.project_id
}

resource "google_storage_bucket_iam_member" "gsa_bucket_access" {
  count  = local.cfg.storage_backend == "gcs" ? 1 : 0
  bucket = google_storage_bucket.kellnr_bucket[0].name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.kellnr_gsa.email}"
}
