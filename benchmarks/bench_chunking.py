"""Benchmark harness for FastCDC content-defined chunking performance."""
import os
import time
from vouch.chunking import chunk_stream, DEFAULT_AVG_CHUNK_SIZE

def run_chunking_benchmark(size_mb: int = 16) -> None:
    data = os.urandom(size_mb * 1024 * 1024)
    start_time = time.perf_counter()
    chunks = list(chunk_stream(data, avg_size=DEFAULT_AVG_CHUNK_SIZE))
    elapsed = time.perf_counter() - start_time
    throughput = (size_mb / elapsed)
    
    print(f"Processed {size_mb} MB in {elapsed:.4f}s ({throughput:.2f} MB/s)")
    print(f"Generated {len(chunks)} chunks, avg size: {len(data)/max(1, len(chunks)):.1f} bytes")

if __name__ == "__main__":
    print("Running FastCDC Chunking Benchmark...")
    run_chunking_benchmark()
