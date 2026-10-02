import asyncio
import time
import subprocess
import numpy as np
import httpx
from httpx_socks import AsyncProxyTransport

async def measure_latency(proxy_url, target_url):
    transport = AsyncProxyTransport.from_url(proxy_url)
    async with httpx.AsyncClient(transport=transport, timeout=10.0) as client:
        start_time = time.time()
        try:
            response = await client.get(target_url)
            end_time = time.time()
            if response.status_code == 200:
                return end_time - start_time
        except Exception as e:
            return None
    return None

async def run_profiling():
    print("[+] Starting Latency Profiling (Circuit Build & Connect)")
    proxy_url = "socks5://127.0.0.1:9050"
    target_url = "http://1.1.1.1" # Using Cloudflare DNS endpoint over HTTP for testing
    
    num_requests = 100
    concurrent_requests = 10
    
    latencies = []
    
    semaphore = asyncio.Semaphore(concurrent_requests)
    
    async def worker():
        async with semaphore:
            return await measure_latency(proxy_url, target_url)
            
    tasks = [worker() for _ in range(num_requests)]
    results = await asyncio.gather(*tasks)
    
    for r in results:
        if r is not None:
            latencies.append(r)
            
    if not latencies:
        print("[-] All requests failed.")
        return
        
    p50 = np.percentile(latencies, 50)
    p95 = np.percentile(latencies, 95)
    p99 = np.percentile(latencies, 99)
    
    print(f"Results for {len(latencies)} successful circuits:")
    print(f"  p50: {p50*1000:.2f} ms")
    print(f"  p95: {p95*1000:.2f} ms")
    print(f"  p99: {p99*1000:.2f} ms")

if __name__ == "__main__":
    asyncio.run(run_profiling())
