import sys
import urllib.request
import urllib.error
import time
import json
import os

def get_subpath(name):
    length = len(name)
    if length == 1:
        return f"1/{name}"
    elif length == 2:
        return f"2/{name}"
    elif length == 3:
        return f"3/{name[0]}/{name}"
    else:
        return f"{name[0:2]}/{name[2:4]}/{name}"

def get_static_ip_from_state():
    possible_paths = [
        "terraform/infra/terraform.tfstate",
        "../terraform/infra/terraform.tfstate",
        "../../terraform/infra/terraform.tfstate",
    ]
    for path in possible_paths:
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    state = json.load(f)
                    ip = state.get("outputs", {}).get("kellnr_static_ip_address", {}).get("value")
                    if ip:
                        print(f"Found static IP in state file ({path}): {ip}")
                        return ip
            except Exception as e:
                print(f"Error reading state file {path}: {e}")
    return None

def main():
    packages_file = "packages.txt"
    
    ip = None
    if len(sys.argv) > 1:
        ip = sys.argv[1]
        print(f"Using IP provided as argument: {ip}")
    else:
        ip = get_static_ip_from_state()
        
    if not ip:
        print("Error: Could not determine GKE IP address.")
        print("Usage: python3 warm_cdn.py <GKE_IP>")
        print("Or run from a directory containing the terraform/infra/terraform.tfstate file.")
        sys.exit(1)
        
    base_url = f"http://{ip}/api/v1/cratesio"
    
    try:
        with open(packages_file, "r") as f:
            packages = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    except Exception as e:
        print(f"Error reading packages file: {e}")
        sys.exit(1)
        
    print(f"Loaded {len(packages)} packages to warm up in CDN.")
    
    success_count = 0
    for i, pkg in enumerate(packages):
        subpath = get_subpath(pkg)
        metadata_url = f"{base_url}/{subpath}"
        
        start_time = time.time()
        print(f"[{i+1}/{len(packages)}] Fetching metadata for {pkg} via CDN...", end="", flush=True)
        try:
            # Fetch metadata without Cache-Control bypass to allow CDN to cache it
            req = urllib.request.Request(metadata_url)
            with urllib.request.urlopen(req) as response:
                content = response.read()
                # Check headers to see if it was a cache hit (for informational purposes)
                headers = response.info()
                via = headers.get("Via", "Unknown")
                cache_status = headers.get("X-Cache", "Unknown") # Google CDN might use different headers, but we can log 'Via'
                
            latency = (time.time() - start_time) * 1000
            print(f" OK ({latency:.1f}ms) [Via: {via}]")
            success_count += 1
            
        except urllib.error.HTTPError as e:
            print(f" Failed: HTTP {e.code} {e.reason}")
        except Exception as e:
            print(f" Error: {e}")
            
    print(f"CDN Warm up completed. Successfully warmed up {success_count}/{len(packages)} packages in CDN.")

if __name__ == "__main__":
    main()
