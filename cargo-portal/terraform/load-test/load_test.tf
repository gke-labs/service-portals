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
        node_selector = var.node_selector

        affinity {
          pod_anti_affinity {
            required_during_scheduling_ignored_during_execution {
              label_selector {
                match_expressions {
                  key      = "app"
                  operator = "In"
                  values   = ["kellnr-stress", "kellnr"]
                }
              }
              topology_key = "kubernetes.io/hostname"
            }
          }
        }



        container {
          name    = "load-generator"
          image   = "google/cloud-sdk:slim"
          command = ["/bin/bash", "-c"]
          args    = [
            <<-EOT
            cat << 'EOF' > /tmp/gcs_helper.py
            import sys, urllib.request, json, os, urllib.parse
            def get_token():
                req = urllib.request.Request("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", headers={"Metadata-Flavor": "Google"})
                return json.loads(urllib.request.urlopen(req).read())["access_token"]
            def download(bucket, object_path, dest_path):
                token = get_token()
                encoded_path = urllib.parse.quote(object_path, safe='')
                url = f"https://storage.googleapis.com/download/storage/v1/b/{bucket}/o/{encoded_path}?alt=media"
                req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
                with urllib.request.urlopen(req) as response:
                    with open(dest_path, "wb") as f:
                        f.write(response.read())
            def upload(bucket, src_path, object_path):
                token = get_token()
                encoded_path = urllib.parse.quote(object_path, safe='')
                url = f"https://storage.googleapis.com/upload/storage/v1/b/{bucket}/o?uploadType=media&name={encoded_path}"
                with open(src_path, "rb") as f:
                    data = f.read()
                req = urllib.request.Request(url, data=data, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/octet-stream"}, method="POST")
                with urllib.request.urlopen(req) as response:
                    pass
            def check(bucket):
                try:
                    token = get_token()
                    url = f"https://storage.googleapis.com/storage/v1/b/{bucket}/o?maxResults=1"
                    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
                    with urllib.request.urlopen(req) as response:
                        pass
                    return True
                except Exception as e:
                    return False
            if __name__ == "__main__":
                cmd, bucket = sys.argv[1], sys.argv[2]
                if cmd == "download": download(bucket, sys.argv[3], sys.argv[4])
                elif cmd == "upload": upload(bucket, sys.argv[3], sys.argv[4])
                elif cmd == "check": sys.exit(0 if check(bucket) else 1)
            EOF

            until python3 /tmp/gcs_helper.py check ${google_storage_bucket.load_test_bucket.name}; do
              echo "Waiting for Workload Identity credentials..."
              sleep 5
            done
            python3 /tmp/gcs_helper.py download ${google_storage_bucket.load_test_bucket.name} stress-test /tmp/stress-test
            python3 /tmp/gcs_helper.py download ${google_storage_bucket.load_test_bucket.name} packages.txt /tmp/packages.txt
            chmod +x /tmp/stress-test
            /tmp/stress-test
            python3 /tmp/gcs_helper.py upload ${google_storage_bucket.load_test_bucket.name} /tmp/stress_test_result.csv results/stress_test_$${POD_NAME}.csv
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
