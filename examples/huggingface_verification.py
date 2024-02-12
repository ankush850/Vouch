"""Example script: safely loading PyTorch weights after Vouch cryptographic verification."""

import subprocess
import sys
from pathlib import Path


def load_verified_model(publisher: str, artifact: str, version: str, dest_dir: Path):
    print(f"[*] Fetching and verifying {publisher}/{artifact}@{version}...")
    dest_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable, "-m", "vouch.cli.main",
        "fetch",
        "--publisher", publisher,
        "--artifact", artifact,
        "--version", version,
        "--out", str(dest_dir),
    ]

    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Verification or fetch failed! Error:\n{res.stderr}")

    print("[+] Cryptographic verification passed!")
    model_weight_file = dest_dir / "weights.safetensors"
    if not model_weight_file.exists():
        model_weight_file = dest_dir / "pytorch_model.bin"

    print(f"[+] Safe model ready for loading at: {model_weight_file}")
    return model_weight_file


if __name__ == "__main__":
    out_dir = Path("./models/safe_checkpoint")
    print("Vouch HuggingFace Safe Model Loader initialized.")
