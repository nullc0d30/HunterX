---
layout: post
title: HunterX Goes Open Source — Apache 2.0 Relicensing
description: >-
  HunterX is now fully open source under the Apache License 2.0. Learn about
  the licensing change, what it means for users and contributors, and the
  future of the project.
date: 2026-07-22
author: Ahmed Awad (NullC0d3)
categories: [releases, community]
---

## HunterX Goes Open Source

Today I'm excited to announce that HunterX — the AI-assisted vulnerability scanner and Red Team framework — is now fully open source under the **Apache License 2.0**.

## Why Apache 2.0?

Apache 2.0 is the industry standard for security tools. It's used by OWASP ZAP, Kubernetes, TensorFlow, and thousands of other projects. The license offers:

- **Permissive terms**: Fork, modify, distribute freely
- **Attribution required**: Proper credit to the original work
- **Patent protection**: Grants patent rights from contributors
- **No GPL-style copyleft**: Can be used in proprietary environments

## What Changed

- All 57 Python source files updated to `SPDX-License-Identifier: Apache-2.0`
- All documentation files updated
- NOTICE file added with third-party attributions
- CONTRIBUTING.md updated with DCO requirement
- Docker Hub images rebuilt with Apache 2.0 labels

## What This Means

- **For users**: You can now use HunterX without concerns about the prior Proprietary license
- **For contributors**: You retain copyright, grant a license to the project
- **For the community**: You can fork, modify, and redistribute

## What's Next

The [roadmap]({{ '/roadmap' | relative_url }}) remains unchanged. v4.1 will focus on gRPC, OAuth2, Redis queue, and TUI. v5.0 will bring autonomous agent capabilities.

Thank you to everyone who has supported the project. This is just the beginning.
