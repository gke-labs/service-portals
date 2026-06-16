#!/usr/bin/env python3
import urllib.request
import json
import sys
import time

def fetch_popular_crates(limit=1000):
    crates = []
    page = 1
    per_page = 100
    
    while len(crates) < limit:
        req = urllib.request.Request(
            f"https://crates.io/api/v1/crates?page={page}&per_page={per_page}&sort=downloads",
            headers={'User-Agent': 'KellnrProxyLoadTester (armentrout@google.com)'}
        )
        
        try:
            with urllib.request.urlopen(req) as response:
                data = json.loads(response.read().decode())
                
            page_crates = data.get('crates', [])
            if not page_crates:
                break
                
            for c in page_crates:
                crates.append(c['name'])
                if len(crates) >= limit:
                    break
            
            print(f"Fetched page {page}... Total crates so far: {len(crates)}")
            page += 1
            time.sleep(0.5)
            
        except Exception as e:
            print(f"Error fetching page {page}: {e}")
            break
            
    return crates

if __name__ == "__main__":
    limit = 1000
    if len(sys.argv) > 1:
        try:
            limit = int(sys.argv[1])
        except ValueError:
            pass
            
    print(f"Fetching top {limit} popular crates from crates.io...")
    crates = fetch_popular_crates(limit)
    
    out_file = "packages.txt"
    with open(out_file, "w") as f:
        for crate in crates:
            f.write(f"{crate}\n")
            
    print(f"Saved {len(crates)} crate names to {out_file}")
