output "load_test_bucket_name" {
  value = google_storage_bucket.load_test_bucket.name
}

output "stress_instructions" {
  value = <<EOF

Stress testing infrastructure configured!

To run the load simulations:
1. Compile the stress-test binary locally for Linux x86_64:
   cargo build --release --manifest-path ../../stress-test/Cargo.toml

2. Copy the compiled binary and packages.txt into the GCS load-test bucket:
   gcloud storage cp ../../stress-test/target/release/stress-test gs://${google_storage_bucket.load_test_bucket.name}/stress-test

   (Optional) Fetch and copy the top 1000 popular crates to load-test real-world proxy caching:
   python3 ../../stress-test/get_popular_crates.py 1000
   gcloud storage cp packages.txt gs://${google_storage_bucket.load_test_bucket.name}/packages.txt

3. Trigger the stress test by running:
   terraform apply

4. Once the job completes, you can copy the CSV results back from the GCS bucket to analyze them:
   gcloud storage cp -r gs://${google_storage_bucket.load_test_bucket.name}/results/ .

EOF
}
