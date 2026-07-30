---
layout: default
title: Installation — HunterX v6.0.0
keywords: cross-platform security framework, pip install hunterx, offensive security installation
description: >-
  Install HunterX on Linux, macOS, and Windows. Cross-platform Python
  framework for offensive security — install via pip, pipx, install.sh,
  Docker, or from source. System requirements and package details for Ubuntu,
  Debian, Fedora, Arch, and Alpine. Apache 2.0 open-source.
permalink: /installation/
---

## Installation

HunterX requires **Python 3.11+** and is available on Linux, macOS, and Windows.

---

## pip (Recommended)

```bash
pip install hunterx
```

After installation, the `hunterx` command is available globally.

## pipx

```bash
pipx install hunterx
```

## Linux Install Script

The one-line installer auto-detects your distribution and installs all system dependencies:

```bash
# System-wide installation (requires root)
curl -sSL https://raw.githubusercontent.com/nullc0d30/HunterX/main/install.sh | sudo bash

# User-local installation (no root required)
curl -sSL https://raw.githubusercontent.com/nullc0d30/HunterX/main/install.sh | bash -s -- --user

# Uninstall
curl -sSL https://raw.githubusercontent.com/nullc0d30/HunterX/main/install.sh | sudo bash -s -- --uninstall
```

The installer supports:
- `--user` — Install to `~/.local` (no sudo needed)
- `--uninstall` — Remove HunterX and all symlinks
- Automatic checksum verification for downloaded packages
- Case-variant symlinks: `HunterX`, `Hunterx`, `hunterX`, `HUNTERX`

### Per-Distribution Packages

| Distribution | System Packages | Command |
|---|---|---|
| **Ubuntu / Debian** | `python3 python3-pip python3-venv` | `sudo apt-get install -y python3 python3-pip python3-venv` |
| **Fedora / RHEL** | `python3 python3-pip python3-venv` | `sudo dnf install -y python3 python3-pip python3-venv` |
| **Arch** | `python python-pip` | `sudo pacman -S --noconfirm python python-pip` |
| **Alpine** | `python3 py3-pip` | `sudo apk add python3 py3-pip` |
| **openSUSE** | `python3 python3-pip python3-venv` | `sudo zypper install -y python3 python3-pip python3-venv` |

The installer creates the `hunterx` command (plus case-variant symlinks `HunterX`, `Hunterx`, `hunterX`, `HUNTERX`) in `/usr/local/bin`.

## From Source

```bash
git clone https://github.com/nullc0d30/HunterX.git
cd HunterX
pip install .
hunterx --version
```

## Docker

```bash
# Pull the latest image
docker pull nullc0d30/hunterx:latest

# Run a scan
docker run --rm -v $(pwd)/reports:/data nullc0d30/hunterx:latest scan target.com

# API mode
docker run --rm -p 8443:8443 nullc0d30/hunterx:latest api --port 8443

# With AI analysis
docker run --rm -v $(pwd)/reports:/data \
    -e OPENAI_API_KEY=sk-... \
    nullc0d30/hunterx:latest \
    scan target.com --ai --ai-model gpt-4
```

## Optional Extras

```bash
# API server support (FastAPI + Uvicorn)
pip install hunterx[api]

# Browser intelligence (Playwright)
pip install hunterx[browser]

# Graph visualization (Graphviz)
pip install hunterx[graphviz]

# ML clustering (scikit-learn)
pip install hunterx[ml]

# All extras
pip install hunterx[all]
```

## Verify Installation

```bash
hunterx --version
hunterx doctor
```

---

## Next Steps

- [Quickstart Guide](quickstart) — Run your first scan in 5 minutes
- [CLI Reference](cli) — Complete command reference
- [Docker Guide](Docker_Guide) — Production container deployment
