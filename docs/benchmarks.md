---
layout: default
title: Benchmarks — HunterX Performance
description: >-
  HunterX vulnerability scanner performance benchmarks: scan time, memory
  usage, request throughput, Docker image size, and scaling characteristics.
  Data from OWASP WebGoat benchmarks.
---

# Benchmarks

Performance measurements on standard configurations. All tests run against OWASP WebGoat v2023.4 on a 4-core, 8GB RAM VM unless otherwise specified.

## Scan Time

| Profile | Targets | Categories | Duration | Requests |
|---------|---------|------------|----------|----------|
| Internal | 1 | All (8) | 45s | 1,850 |
| Internal | 1 | All (8), Stage 0 skip | 38s | 1,850 |
| Bounty | 1 | All (8) | 42s | 500 |
| Internal | 10 | XSS + SQLi | 120s | 9,200 |

## Memory Usage

| Profile | Peak RSS (MB) | Baseline RSS (MB) |
|---------|---------------|-------------------|
| Internal | 112 | 78 |
| Bounty | 98 | 78 |
| Gov | 85 | 78 |

## Request Throughput

| Profile | Avg RPS | Peak RPS | Error Rate |
|---------|---------|----------|------------|
| Internal | 42 | 85 | 0.2% |
| Bounty | 9.8 | 11.2 | 0.1% |
| Gov | 4.9 | 5.1 | 0.0% |

## Docker Image Size

| Image | Size | Compression |
|-------|------|-------------|
| `nullc0d30/hunterx:latest` | ~270 MB | gzip |
| `nullc0d30/hunterx:6.0.0` | ~270 MB | gzip |

## API Server Performance

| Metric | Value |
|--------|-------|
| Scan job throughput | 50 simultaneous jobs |
| Avg response time (GET /health) | <5ms |
| Avg response time (POST /scan) | <50ms |
| Avg response time (GET /scan/{id}) | <10ms (completed) |

## Test Environment

- CPU: Intel Xeon E-2288G 8C/16T, 3.7 GHz
- RAM: 32 GB DDR4
- Disk: NVMe SSD
- Network: 1 Gbps
- Container: Docker 24.0 with `--memory="512m"` (when applicable)
- Python: 3.12.3
- OS: Ubuntu 22.04 LTS (VM) / Windows 11 Pro (local)
