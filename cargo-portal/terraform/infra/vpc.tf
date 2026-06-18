resource "google_compute_network" "kellnr_network" {
  name                    = "kellnr-network"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "kellnr_subnet" {
  name                     = "kellnr-subnet"
  ip_cidr_range            = "10.128.0.0/20"
  network                  = google_compute_network.kellnr_network.id
  region                   = var.region
  private_ip_google_access = true
}

resource "google_compute_router" "kellnr_router" {
  name    = "kellnr-router"
  network = google_compute_network.kellnr_network.id
  region  = var.region
}

resource "google_compute_address" "nat_ip" {
  name   = "kellnr-nat-ip"
  region = var.region
}

resource "google_compute_router_nat" "kellnr_nat" {
  name                               = "kellnr-nat"
  router                             = google_compute_router.kellnr_router.name
  region                             = var.region
  nat_ip_allocate_option             = "MANUAL_ONLY"
  nat_ips                            = [google_compute_address.nat_ip.self_link]
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}

# Global Static IP for GKE Ingress (HTTPS Load Balancer)
resource "google_compute_global_address" "kellnr_static_ip" {
  count   = local.cfg.enable_cdn ? 1 : 0
  name    = "kellnr-static-ip"
  project = var.project_id
}

# Cloud Armor Policy to protect Load Balancer Edge
resource "google_compute_security_policy" "cloud_armor_policy" {
  count   = local.cfg.enable_cdn ? 1 : 0
  name    = "kellnr-security-policy"
  project = var.project_id

  rule {
    action   = "allow"
    priority = "1000"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = concat(["${google_compute_address.nat_ip.address}/32"], var.allowed_ip_ranges)
      }
    }
    description = "Allow access from approved ranges and Cloud NAT"
  }

  rule {
    action   = "deny(403)"
    priority = "2147483647"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Default deny rule"
  }
}
