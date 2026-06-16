resource "kubernetes_pod" "kellnr_helper" {
  metadata {
    name      = "kellnr-helper"
    namespace = "kellnr"
  }

  spec {
    volume {
      name = "kellnr-storage-volume"
      persistent_volume_claim {
        claim_name = "kellnr-storage-pvc"
      }
    }

    container {
      name    = "helper"
      image   = "ubuntu:22.04"
      command = ["sleep", "3600"]

      volume_mount {
        name       = "kellnr-storage-volume"
        mount_path = "/data"
      }
    }
  }
}

resource "kubernetes_job" "kellnr_stress_job" {
  metadata {
    name      = "kellnr-stress-job"
    namespace = "kellnr"
  }

  spec {
    parallelism = var.parallelism
    completions = var.completions
    backoff_limit = 0

    template {
      metadata {
        labels = {
          app = "kellnr-stress"
        }
      }

      spec {
        restart_policy = "Never"

        volume {
          name = "kellnr-storage-volume"
          persistent_volume_claim {
            claim_name = "kellnr-storage-pvc"
          }
        }

        container {
          name    = "load-generator"
          image   = "ubuntu:22.04"
          command = ["/bin/bash", "-c"]
          args    = ["chmod +x /data/stress-test && /data/stress-test"]

          env {
            name  = "GKE_IP"
            value = data.terraform_remote_state.infra.outputs.kellnr_static_ip_address
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
            name  = "CSV_OUT"
            value = "/data/stress_test_option_b_$(POD_NAME).csv"
          }

          volume_mount {
            name       = "kellnr-storage-volume"
            mount_path = "/data"
          }

          resources {
            limits = {
              cpu    = "2"
              memory = "2Gi"
            }
            requests = {
              cpu    = "500m"
              memory = "512Mi"
            }
          }
        }
      }
    }
  }
}
