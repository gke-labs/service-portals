resource "google_storage_bucket" "load_test_bucket" {
  name          = "kellnr-load-test-${data.terraform_remote_state.infra.outputs.project_id}"
  project       = data.terraform_remote_state.infra.outputs.project_id
  location      = data.terraform_remote_state.infra.outputs.region
  force_destroy = true
  
  uniform_bucket_level_access = true
}

resource "google_storage_bucket_iam_member" "kellnr_gsa_storage_admin" {
  bucket = google_storage_bucket.load_test_bucket.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${data.terraform_remote_state.infra.outputs.gsa_email}"
}

resource "kubernetes_job" "kellnr_stress_job" {
  wait_for_completion = false
  metadata {
    name      = "kellnr-stress-job"
    namespace = "kellnr"
  }

  spec {
    parallelism   = var.parallelism
    completions   = var.completions
    backoff_limit = 3

    template {
      metadata {
        labels = {
          app = "kellnr-stress"
        }
      }

      spec {
        restart_policy       = "OnFailure"
        service_account_name = "kellnr-ksa"

        container {
          name    = "load-generator"
          image   = "google/cloud-sdk:slim"
          command = ["/bin/bash", "-c"]
          args    = [
            <<-EOT
            gsutil cp gs://${google_storage_bucket.load_test_bucket.name}/stress-test /tmp/stress-test
            gsutil cp gs://${google_storage_bucket.load_test_bucket.name}/packages.txt /tmp/packages.txt
            chmod +x /tmp/stress-test
            /tmp/stress-test
            gsutil cp /tmp/stress_test_result.csv gs://${google_storage_bucket.load_test_bucket.name}/results/stress_test_$${POD_NAME}.csv
            EOT
          ]

          env {
            name  = "GKE_IP"
            value = data.terraform_remote_state.infra.outputs.cfg.enable_cdn ? data.terraform_remote_state.infra.outputs.kellnr_static_ip_address : "kellnr-service.kellnr.svc.cluster.local"
          }

          env {
            name  = "CONCURRENCY"
            value = tostring(var.concurrency)
          }

          env {
            name  = "DURATION"
            value = tostring(var.duration)
          }

          env {
            name = "POD_NAME"
            value_from {
              field_ref {
                field_path = "metadata.name"
              }
            }
          }

          env {
            name  = "REGISTRY_PATH"
            value = var.registry_path
          }

          env {
            name  = "PACKAGES_FILE"
            value = "/tmp/packages.txt"
          }

          env {
            name  = "CSV_OUT"
            value = "/tmp/stress_test_result.csv"
          }

          resources {
            limits = {
              cpu    = "2"
              memory = "2Gi"
            }
            requests = {
              cpu    = "2"
              memory = "2Gi"
            }
          }
        }
      }
    }
  }
}
