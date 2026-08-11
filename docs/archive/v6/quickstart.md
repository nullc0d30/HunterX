---
layout: default
title: Quickstart — HunterX v6.0.0
keywords: HunterX Quickstart, Getting Started, First Scan
description: >-
  Get started with HunterX v6.0.0 in minutes. Run your first scan and see results.
---
# Quickstart

Follow these steps to run your first scan with HunterX.

## Step 1: Installation

If you haven't installed HunterX yet, see the [Installation](/installation/) guide.

## Step 2: Initialize Configuration

Run the setup command to create the default configuration:

```bash
hunterx setup
```

## Step 3: Update Feeds (Optional but Recommended)

Update the vulnerability and threat intelligence feeds:

```bash
hunterx feeds update
```

## Step 4: Run Your First Scan

Scan a target (replace `example.com` with your target):

```bash
hunterx scan example.com
```

## Step 5: View Results

- Results are displayed in the terminal.
- A detailed report is saved in the `reports/` directory.
- You can also view results in JSON format:

```bash
hunterx scan example.com --output json
```

## Understanding the Output

The scan will perform:
1. Reconnaissance (subdomain discovery, port scanning)
2. Vulnerability assessment
3. Exploitation attempt (if configured and safe)
4. Reporting

## Next Steps

- Explore the [CLI Reference](/cli/) for advanced options.
- Check out the [Features](/features/) to understand HunterX capabilities.
- Try a [Tutorial](/tutorials/01-basic-scanning/) for hands-on learning.
