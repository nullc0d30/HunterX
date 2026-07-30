---
layout: default
title: systemd Service — HunterX v6.0.0
description: >-
  Run HunterX as a systemd service for production deployments.
  Includes service file, environment configuration, and management commands.
permalink: /systemd/
---

## systemd Service

This guide explains how to run HunterX as a systemd service for production deployments.

---

## Prerequisites

- HunterX installed via `pip install hunterx` or from source
- Root or sudo access
- A dedicated `hunterx` user and group (or run as an existing user)

---

## Service File

A sample service file is provided at `examples/systemd/hunterx.service`:

```
[Unit]
Description=HunterX — AI-Assisted Offensive Security Framework
Documentation=https://nullc0d30.github.io/HunterX
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=hunterx
Group=hunterx
WorkingDirectory=/opt/hunterx
Environment=HX_LOG_LEVEL=INFO
Environment=HX_CONFIG=/opt/hunterx/hunterx.yaml
Environment=HX_DATA_DIR=/var/lib/hunterx
Environment=HX_REPORT_DIR=/var/lib/hunterx/reports
ExecStart=/usr/local/bin/hunterx api --host 0.0.0.0 --port 8443
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=hunterx
LimitNOFILE=65536
PrivateTmp=true
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=true
ReadWritePaths=/var/lib/hunterx

[Install]
WantedBy=multi-user.target
```

---

## Installation

### 1. Create the hunterx user

```bash
sudo groupadd -r -g 999 hunterx
sudo useradd -r -g hunterx -u 999 -d /opt/hunterx -s /sbin/nologin hunterx
```

### 2. Create directories

```bash
sudo mkdir -p /opt/hunterx /var/lib/hunterx/reports
sudo chown -R hunterx:hunterx /opt/hunterx /var/lib/hunterx
```

### 3. Copy configuration

```bash
sudo cp hunterx.yaml /opt/hunterx/
sudo chown hunterx:hunterx /opt/hunterx/hunterx.yaml
```

### 4. Install the service file

```bash
sudo cp examples/systemd/hunterx.service /etc/systemd/system/
sudo systemctl daemon-reload
```

### 5. Enable and start

```bash
sudo systemctl enable hunterx
sudo systemctl start hunterx
```

---

## Management

### Check status

```bash
sudo systemctl status hunterx
```

### View logs

```bash
sudo journalctl -u hunterx -f
```

### Restart

```bash
sudo systemctl restart hunterx
```

### Reload configuration

```bash
sudo systemctl reload hunterx
```

### Stop

```bash
sudo systemctl stop hunterx
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `HX_LOG_LEVEL` | `INFO` | Log level: `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `HX_CONFIG` | `hunterx.yaml` | Path to configuration file |
| `HX_DATA_DIR` | `/var/lib/hunterx` | Data directory for payloads and state |
| `HX_REPORT_DIR` | `/var/lib/hunterx/reports` | Report output directory |

---

## Security Hardening

The service file applies the following security hardening:

| Directive | Purpose |
|---|---|
| `PrivateTmp=true` | Isolates `/tmp` access |
| `NoNewPrivileges=yes` | Prevents privilege escalation |
| `ProtectSystem=full` | Makes `/usr` and `/etc` read-only |
| `ProtectHome=true` | Blocks access to `/home`, `/root`, `/run/user` |
| `ReadWritePaths` | Limits writable paths to the data directory |

---

## Troubleshooting

### Service fails to start

```bash
sudo journalctl -u hunterx -n 50 --no-pager
```

### Permission denied

```bash
sudo ls -la /opt/hunterx/
sudo chown -R hunterx:hunterx /opt/hunterx
```

### Port already in use

```bash
sudo ss -tulpn | grep 8443
```
