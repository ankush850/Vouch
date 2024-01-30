"""Benchmark harness for BLAKE3 and SHA-256 multi-hash digest generation throughput."""
import os
import time
from vouch.hashing import hash_bytes, compute_multihash

def run_hashing_benchmark(size_mb: int = 64) -> None:
    data = os.urandom(size_mb * 1024 * 1024)
    start_time = time.perf_counter()
    digest = hash_bytes(data)
    elapsed = time.perf_counter() - start_time
    throughput = size_mb / elapsed
    
    print(f"Hashed {size_mb} MB in {elapsed:.4f}s ({throughput:.2f} MB/s)")
    print(f"Digest: {digest}")

if __name__ == "__main__":
    print("Running BLAKE3 Hashing Benchmark...")
    run_hashing_benchmark()
