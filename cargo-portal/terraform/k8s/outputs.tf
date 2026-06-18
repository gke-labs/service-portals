output "kellnr_ingress_ip" {
  value       = local.cfg.enable_cdn ? data.terraform_remote_state.infra.outputs.kellnr_static_ip_address : "N/A"
  description = "The public Ingress Load Balancer IP address."
}

output "instruction_steps" {
  value = <<EOF

Workload deployment initiated!

Active Option: ${data.terraform_remote_state.infra.outputs.cfg.enable_cdn ? "GKE + CDN" : "GKE-Only Internal"}
Storage Backend: ${data.terraform_remote_state.infra.outputs.cfg.storage_backend == "gcs" ? "Cloud Storage (GCS Bucket)" : "Cloud Filestore (NFS PVC)"}

Next steps:
${data.terraform_remote_state.infra.outputs.cfg.enable_cdn ? "1. Access Kellnr Caching Proxy from your local Cargo client at: http://${data.terraform_remote_state.infra.outputs.kellnr_static_ip_address}/" : "1. The deployment is internal-only. You can verify it by running the stress generator Job within GKE."}
2. Retrieve the dynamically generated DB password using kubectl:
   kubectl get secret kellnr-secrets -n kellnr -o jsonpath="{.data.db_password}" | base64 --decode
EOF
  description = "Post-deployment instructions."
}
