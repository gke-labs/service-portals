resource "google_filestore_instance" "kellnr_filestore" {
  count    = local.cfg.storage_backend == "filestore" ? 1 : 0
  name     = "kellnr-filestore"
  location = var.zone
  tier     = "STANDARD"

  file_shares {
    capacity_gb = 1024 # Filestore Standard tier requires a minimum of 1TiB (1024 GB)
    name        = "vol1"
  }

  networks {
    network = google_compute_network.kellnr_network.name
    modes   = ["MODE_IPV4"]
  }
}
