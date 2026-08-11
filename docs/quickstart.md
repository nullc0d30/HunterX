---
layout: default
title: Quickstart — HunterX v7
keywords: HunterX Quickstart, HunterX Usage, first mission
description: >-
  Get HunterX v7 installed and run your first security-assessment mission in
  minutes.
---

# Quickstart

This guide gets HunterX v7 installed and walks you through a first, safe,
authorized mission.

## Prerequisites

- Python 3.11+
- Linux, macOS or Windows
- Authorization to test the target you exercise (see
  [Responsible Use](/responsible-use/))

## Install

```bash
# System install (Linux/macOS)
curl -sSL https://raw.githubusercontent.com/nullc0d30/HunterX/main/install.sh | sudo bash

# Or install the current package from source / PyPI
python -m pip install "hunterx[api,db]"
```

Verify:

```bash
hunterx version        # HunterX v7.0.0
hunterx help           # command list
hunterx config         # resolved configuration
```

## Run your first mission

HunterX v7 organizes work as **missions** (`hunterx mission` / `hunterx hunt`).
Start with an authorized target:

```bash
# Plan and start a full-spectrum hunt mission
hunterx hunt full_security_assessment https://example.com

# Track it
hunterx hunt status <mission_id>
hunterx hunt surface <mission_id>
```

## Explore the toolchain

```bash
# Inspect the registered security toolchain
hunterx tools list
hunterx tools capabilities
hunterx tools health
```

## Manage findings and reports

```bash
hunterx finding list <mission_id>
hunterx report generate <finding_id>
hunterx report export <report_id> markdown
```

## Next steps

- [CLI Reference](/cli/) — every `hunterx` command
- [Configuration](/configuration/) — `HUNTERX_*` environment overrides
- [Features](/features/) — platform capabilities
- [Documentation Hub](/documentation/) — the full v7 guide set
