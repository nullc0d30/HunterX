---
layout: default
title: Installation — HunterX v7
keywords: HunterX Installation, Setup, Requirements, PyPI, pip install hunterxsec
description: >-
  Install HunterX v7 on Linux, macOS or Windows, from PyPI, the installer
  script, source, or Docker.
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

## 2. PyPI

Install from [PyPI](https://pypi.org/project/hunterxsec/) with pip:

```bash
python -m pip install hunterxsec
```

Optional extras (for example the REST API):

```bash
python -m pip install "hunterxsec[api,db]"
```

## 3. Source

```bash
git clone https://github.com/nullc0d30/HunterX.git
cd HunterX
python -m pip install -e ".[api,db,dev]"
```

## 4. Docker

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

## External tool readiness & provisioning

HunterX orchestrates *external* security tools (nmap, subfinder, nuclei, ffuf,
...). After installing HunterX itself, establish the base environment and check
which external tools are available:

```bash
hunterx install                        # base environment (detect + verify tools)
hunterx tools check                    # per-tool readiness + capability coverage
hunterx tools audit                    # integration maturity (knowledge + runtime)
hunterx tools install --profile recon  # provision missing recon tools
hunterx tools install --profile full   # provision the complete external toolchain
```

The `install.sh` script is a full **environment bootstrapper**: it detects the
platform and available runtimes/package managers, installs the HunterX package,
invokes the canonical Tool Readiness layer to discover/verify/provision external
tools, configures PATH (current process and future shells, idempotent), then
runs the final readiness verification and reports `INSTALLATION COMPLETE`,
`INSTALLATION COMPLETE — DEGRADED` or `INSTALLATION INCOMPLETE` with exact
reasons.

```bash
./install.sh --profile full     # provision the complete external toolchain
./install.sh --profile recon    # recon toolset
./install.sh --core             # base package + minimal profile
```

Provisioning uses trusted, static installation methods (`apt`/`brew`/`go`/
`cargo`/`pip`/`choco`/...); it is idempotent, never builds commands from target
input, and only invokes runtimes/package managers actually present. A
`hunterx hunt` mission runs a readiness preflight before execution and blocks
explicitly when a required capability has no available tool. See
[Tool Readiness & Auto-Provisioning]({{ '/tool-readiness/' | relative_url }}).

## Database initialization

HunterX v7 uses Alembic migrations. The CLI initializes on demand; for an
explicit migration run:

```bash
alembic upgrade head
```

The database URL defaults to the application data directory —
`<application root>/data/hunterx.db` — resolved at runtime by
`hunterx.config.paths`. Override it with `HUNTERX_DATABASE_URL` or relocate the
data directory with `HUNTERX_DATA_DIR` (see
[Configuration]({{ '/configuration/' | relative_url }})).

## Uninstall

```bash
sudo bash install.sh --uninstall
# or for a user install:
bash install.sh --user --uninstall
```

## Name note

The GitHub repository [nullc0d30/HunterX](https://github.com/nullc0d30/HunterX)
is the canonical home of HunterX, created and maintained by Ahmed Awad (AKA
NullC0d3). The HunterX v7 distribution is published to
[PyPI](https://pypi.org/project/hunterxsec/) as `hunterxsec`; the plain `hunterx`
name on PyPI belongs to a different, unrelated project. The import package and
CLI command are `hunterx` either way, so install with
`pip install hunterxsec` and run `hunterx`.

## Troubleshooting

- `hunterx: command not found` — the install location is not on `PATH`; the
  installer prints the required `export PATH=...`.
- `ModuleNotFoundError: sqlalchemy` — install with the `db` extra:
  `python -m pip install -e ".[db]"` from the source tree.

## Next steps

- [Quickstart]({{ '/quickstart/' | relative_url }}) — run your first mission
- [CLI Reference]({{ '/cli/' | relative_url }}) — command reference
