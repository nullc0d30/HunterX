---
layout: default
title: Reporting Configuration — HunterX v6.0.0
keywords: HunterX Reporting, Output Directory, Evidence Level, Visualization
description: >-
  Reference for HunterX reporting configuration. Learn how to configure output
  directories, evidence levels, and visualization options.
---
# Reporting Configuration

HunterX provides several configuration options to control the output and reporting of scan results.

## Configuration Options

The following reporting-related settings can be configured in `hunterx.yaml`:

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `output_dir` | string | `reports` | Directory where all output files (reports, logs, etc.) are saved. |
| `evidence_level` | string | `medium` | Level of detail included in evidence for findings. Options: `low`, `medium`, `high`. |
| `min_confidence` | float | `0.0` | Minimum confidence threshold (0.0 to 1.0) for a finding to be included in reports. |
| `visual` | string | `cli` | Visualization mode. Options: `cli`, `web`, `off`. |

### Output Directory

The `output_dir` specifies where HunterX will write:

- Scan reports (JSON, HTML, SARIF, etc.)
- Evidence files (requests/response dumps)
- Logs (if enabled)
- Other artifacts

If the directory does not exist, HunterX will attempt to create it.

### Evidence Level

The evidence level controls how much detail is included in the evidence section of each finding:

- **low**: Basic evidence (e.g., request URL, method)
- **medium**: Includes headers and body (truncated if large)
- **high**: Full request and response details (may be large)

### Minimum Confidence

The `min_confidence` setting filters out findings below the specified confidence threshold.
Confidence is calculated based on the strength of evidence and the reliability of the test.

Setting this to `0.0` (default) includes all findings regardless of confidence.
Setting to `1.0` would require absolute certainty (rarely achieved).

### Visualization

The `visual` setting controls whether and how HunterX generates visualizations:

- **cli**: Simple text-based output in the terminal (default)
- **web**: Generates interactive HTML visualizations (requires additional dependencies)
- **off**: Disables visualization generation

## Usage Examples

### Change Output Directory

```yaml
output_dir: ./scan-results
```

### Increase Evidence Detail

```yaml
evidence_level: high
```

### Only Show High-Confidence Findings

```yaml
min_confidence: 0.7
```

### Disable Visualization

```yaml
visual: off
```

## Related Configuration

While not strictly reporting settings, the following configuration sections also affect output:

- **AI Configuration**: When AI is enabled, additional analysis and explanations are included in reports.
- **Out-of-Band (OOB)**: When enabled, OOB findings are included in reports.
- **Presets**: Scan presets (quick, full, stealth) may indirectly affect report volume by changing scan intensity.

## Related Documentation

- [Configuration Reference](/configuration/) - Full configuration file reference
- [CLI Reference](/cli/) - Command-line options for report generation (e.g., `--sarif`, `--graph`, `--format`)
- [Reporting Features](/features/) - Details on report formats and generation
