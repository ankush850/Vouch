# Vouch CLI Cheatsheet

Quick reference for essential Vouch CLI commands.

## Setup & Identity
```bash
# Generate a new Ed25519 signing keypair
vouch keygen --out-key ./keys/root.sec --out-pub ./keys/root.pub

# Initialize an origin store for publisher
vouch publisher init --store /var/vouch/origin --name my-models --root-key ./keys/root.sec
```

## Publishing Artifacts
```bash
# Publish a model directory or weights
vouch publish --store /var/vouch/origin --artifact resnet50 --version 1.0.0 ./weights/

# Mirror an origin store to distribution mirror
vouch mirror sync --source https://origin.internal:8443 --dest /var/vouch/mirror
```

## Verification & Trust
```bash
# Pin publisher root of trust
vouch trust pin --name my-models --root ./keys/root.pub --mirror https://cdn.vouch.network

# Fetch and verify artifact
vouch fetch --publisher my-models --artifact resnet50 --version 1.0.0 --out ./verified_models/

# Verify existing local files
vouch verify --publisher my-models --manifest ./verified_models/vouch.manifest.json
```

## Diagnostics & Operations
```bash
# Run environment diagnostics
vouch doctor

# Check revocation status across pinned publishers
vouch status
```
