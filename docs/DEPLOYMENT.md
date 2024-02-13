# Vouch Production Deployment Guide

Guide for deploying Vouch Origin and Mirror services in highly available production clusters.

## Architecture Topology
- **Origin Store**: Write-only bastion host holding publisher root keys and metadata generation workers.
- **Distribution Mirrors**: Read-only edge servers backed by CDN caching static CAS blobs (`/cas/b3/<hash>`).

## Running with Systemd

### `/etc/systemd/system/vouch-mirror.service`
```ini
[Unit]
Description=Vouch Distribution Mirror Server
After=network.target

[Service]
Type=simple
User=vouch
ExecStart=/usr/local/bin/vouch mirror serve --store /data/vouch-mirror --port 8443 --tls-cert /etc/ssl/vouch.crt --tls-key /etc/ssl/vouch.key
Restart=always
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

## Health Checks
- `GET /healthz` -> 200 OK
- `GET /status` -> Active store statistics
