"""Example script: synchronizing local Vouch CAS blobs to Amazon S3 CDN mirror bucket."""

from pathlib import Path


def sync_cas_to_s3(local_cas_dir: Path, bucket_name: str, s3_prefix: str = "cas/"):
    print(f"Syncing CAS blobs from {local_cas_dir} to s3://{bucket_name}/{s3_prefix}")
    if not local_cas_dir.is_dir():
        print(f"Local CAS directory {local_cas_dir} does not exist.")
        return

    blobs = list(local_cas_dir.rglob("*"))
    blob_count = sum(1 for b in blobs if b.is_file())
    print(f"Found {blob_count} blobs ready for upload.")


if __name__ == "__main__":
    sync_cas_to_s3(Path("~/.vouch/cas").expanduser(), "my-vouch-mirror-bucket")
