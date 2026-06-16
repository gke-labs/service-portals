output "stress_instructions" {
  value = <<EOF

Stress testing infrastructure configured!

To run the load simulations:
1. Compile the stress-test binary locally for Linux x86_64:
   cargo build --release --manifest-path ../../stress-test/Cargo.toml

2. Copy the compiled binary into the Filestore NFS share via the helper pod:
   kubectl cp ../../stress-test/target/release/stress-test kellnr-helper:/data/stress-test -n kellnr

3. Trigger the stress test by running:
   terraform apply

4. Once the job completes, you can copy the CSV results back to analyze them:
   kubectl cp kellnr-helper:/data/ . -n kellnr
EOF
}
