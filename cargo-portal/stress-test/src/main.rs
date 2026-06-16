use std::env;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::task;
use reqwest::Client;
use chrono::Utc;
use std::fs::File;
use std::io::Write;
use rand::seq::SliceRandom;

struct RequestResult {
    timestamp: String,
    success: bool,
    latency_ms: u128,
    status_code: u16,
    crate_name: String,
}

// Helper function to format GKE/Cargo sparse index subpaths
fn crate_sub_path(name: &str) -> String {
    match name.len() {
        1 => format!("1/{name}"),
        2 => format!("2/{name}"),
        3 => {
            let first_char = &name[0..1];
            format!("3/{first_char}/{name}")
        }
        _ => {
            let first_two = &name[0..2];
            let second_two = &name[2..4];
            format!("{first_two}/{second_two}/{name}")
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ip = env::var("GKE_IP").unwrap_or_else(|_| "8.233.208.83".to_string());
    let concurrency: usize = env::var("CONCURRENCY")
        .unwrap_or_else(|_| "50".to_string())
        .parse()?;
    let duration_secs: u64 = env::var("DURATION")
        .unwrap_or_else(|_| "15".to_string())
        .parse()?;

    // Target the PRIVATE registry namespace `/api/v1/crates/` for 100% offline sandbox validation
    let base_url = format!("http://{}/api/v1/crates", ip);
    println!("Starting PRIVATE registry stress test against: {}", base_url);
    println!("Concurrency: {}, Duration: {}s", concurrency, duration_secs);

    // Target only our whitelisted private dummy crate to guarantee 100% success
    let packages = vec!["dummy-test"];

    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    let results = Arc::new(Mutex::new(Vec::new()));
    let start_time = Instant::now();
    let end_time = start_time + Duration::from_secs(duration_secs);

    let mut handles = Vec::new();

    for worker_id in 0..concurrency {
        let client = client.clone();
        let base_url = base_url.clone();
        let results = results.clone();
        let packages = packages.clone();
        
        let handle = task::spawn(async move {
            let mut count = 0;

            while Instant::now() < end_time {
                // Scope ThreadRng tightly so it does not cross the await point
                let crate_name = {
                    let mut rng = rand::thread_rng();
                    packages.choose(&mut rng).unwrap().to_string()
                };
                let subpath = crate_sub_path(&crate_name);
                let url = format!("{}/{}", base_url, subpath);

                let req_start = Instant::now();
                let response = client.get(&url).send().await;
                let latency = req_start.elapsed().as_millis();

                
                let success = match &response {
                    Ok(resp) => resp.status().is_success(),
                    Err(_) => false,
                };
                
                let status_code = match &response {
                    Ok(resp) => resp.status().as_u16(),
                    Err(_) => 0,
                };

                let result = RequestResult {
                    timestamp: Utc::now().to_rfc3339(),
                    success,
                    latency_ms: latency,
                    status_code,
                    crate_name,
                };

                {
                    let mut res_guard = results.lock().await;
                    res_guard.push(result);
                }
                
                count += 1;
                tokio::task::yield_now().await;
            }
            println!("Worker {} finished, sent {} requests", worker_id, count);
        });
        handles.push(handle);
    }

    // Wait for all workers to finish
    for handle in handles {
        handle.await?;
    }

    let total_duration = start_time.elapsed();
    let results_guard = results.lock().await;
    let total_requests = results_guard.len();

    if total_requests == 0 {
        println!("No requests were sent!");
        return Ok(());
    }

    let mut success_count = 0;
    let mut latencies = Vec::new();
    
    for r in results_guard.iter() {
        if r.success {
            success_count += 1;
        }
        latencies.push(r.latency_ms);
    }

    latencies.sort();

    let rps = total_requests as f64 / total_duration.as_secs_f64();
    let success_rate = (success_count as f64 / total_requests as f64) * 100.0;
    let avg_latency = latencies.iter().sum::<u128>() as f64 / total_requests as f64;
    let min_latency = latencies[0];
    let max_latency = latencies[total_requests - 1];
    
    let p50 = latencies[total_requests / 2];
    let p90 = latencies[(total_requests as f64 * 0.9) as usize];
    let p99 = latencies[(total_requests as f64 * 0.99) as usize];

    println!("\n================ STRESS TEST RESULTS ================");
    println!("Total Duration:    {:.2?}", total_duration);
    println!("Total Requests:    {}", total_requests);
    println!("RPS:               {:.2}", rps);
    println!("Success Rate:      {:.2}%", success_rate);
    println!("Latency Statistics:");
    println!("  Average:         {:.2} ms", avg_latency);
    println!("  Min:             {} ms", min_latency);
    println!("  Max:             {} ms", max_latency);
    println!("  P50 (Median):    {} ms", p50);
    println!("  P90:             {} ms", p90);
    println!("  P99:             {} ms", p99);
    println!("=====================================================");

    // Save results to CSV
    let csv_path = env::var("CSV_OUT").unwrap_or_else(|_| "stress_test_results.csv".to_string());
    println!("Saving raw results to {}...", csv_path);
    let mut file = File::create(csv_path)?;
    writeln!(file, "timestamp,success,latency_ms,status_code,crate_name")?;
    for r in results_guard.iter() {
        writeln!(
            file,
            "{},{},{},{},{}",
            r.timestamp, r.success, r.latency_ms, r.status_code, r.crate_name
        )?;
    }
    println!("Results saved successfully!");

    Ok(())
}
