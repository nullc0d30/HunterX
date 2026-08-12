---
layout: default
title: Installation — HunterX v7
keywords: HunterX Installation, Setup, Requirements
description: >-
  Install HunterX v7 on Linux, macOS or Windows, from the installer script,
  source, or Docker.
---

# Installation

HunterX v7 requires **Python 3.11+**. It runs on Linux, macOS and Windows.

## 1. Installer script (Linux / macOS)

The v7 `install.sh` handles environment detection, a virtual environment,
dependency installation, the `hunterx` CLI, required directories, database
initialization and installation verification:

```bash
curl -sSL https://raw.githubusercontent.com/nullc0d30/HunterX/main/install.sh | sudo bash

# User-local install (no root)
curl -sSL https://raw.githubusercontent.com/nullc0d30/HunterX/main/install.sh | bash -s -- --user
```

Re-running the installer is safe (idempotent).

## 2. Source

```bash
git clone https://github.com/nullc0d30/HunterX.git
cd HunterX
python -m pip install -e ".[api,db,dev]"
```

## 3. Docker

Official images are published on
[Docker Hub](https://hub.docker.com/r/nullc0d30/hunterx) as
`nullc0d30/hunterx` (tags `7`, `7.0`, `7.0.0`, `latest`, `stable`):

```bash
docker pull nullc0d30/hunterx:latest

# CLI
docker run --rm nullc0d30/hunterx:latest version

# REST API (FastAPI) — health check at http://localhost:8080/health
docker run -d --name hunterx-api -p 8080:8080 \
  --entrypoint uvicorn nullc0d30/hunterx:latest \
  --factory hunterx.api.app:create_app --host 0.0.0.0 --port 8080
```

Or use the bundled compose stack:

```bash
docker compose up -d hunterx-api
```

## Verify the installation

```bash
hunterx version     # HunterX v7.0.0
hunterx help        # command list
hunterx platform    # platform composition
hunterx config      # resolved configuration
```

## Database initialization

HunterX v7 uses Alembic migrations. The CLI initializes on demand; for an
explicit migration run:

```bash
alembic upgrade head
```

The database URL defaults to `sqlite:///hunterx.db` and can be overridden with
`HUNTERX_DATABASE_URL` (see [Configuration](/configuration/)).

## Uninstall

```bash
sudo bash install.sh --uninstall
# or for a user install:
bash install.sh --user --uninstall
```

## Name note

The GitHub repository [nullc0d30/HunterX](https://github.com/nullc0d30/HunterX)
is the canonical home of HunterX, created and maintained by Ahmed Awad (AKA
NullC0d3). A different, unrelated Python project also uses the name `hunterx`
on PyPI. Always install HunterX from this repository (or `install.sh`) to get
the correct, current project.

## Troubleshooting

- `hunterx: command not found` — the install location is not on `PATH`; the
  installer prints the required `export PATH=...`.
- `ModuleNotFoundError: sqlalchemy` — install with the `db` extra:
  `python -m pip install -e ".[db]"` from the source tree.

## Next steps

- [Quickstart](/quickstart/) — run your first mission
- [CLI Reference](/cli/) — command reference
