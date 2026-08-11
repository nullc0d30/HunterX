---
layout: default
title: Logging Configuration — HunterX v6.0.0
keywords: HunterX Logging, Log Levels, Verbosity
description: >-
  Reference for HunterX logging configuration. Learn how to control log output
  verbosity and destination.
---
# Logging Configuration

HunterX uses Python\'s standard logging module for diagnostic and informational output.
Logging is controlled primarily through verbosity flags on the command line.

## Log Levels

HunterX supports the following log levels (increasing verbosity):

| Level | Description | Corresponding Flag |
|-------|-------------|---------------------|
| `ERROR` | Only error messages | `-q` or `--quiet` |
| `WARNING` | Warnings and errors (default) | (no flag) |
| `INFO` | Informational messages | `-v` or `--verbose` |
| `DEBUG` | Debug-level messages | `-vv` or `-v -v` |

## Configuration Methods

### Command-Line Flags

The primary way to adjust logging verbosity is via the `-v` (verbose) and `-q` (quiet) flags.

These flags can be used together to set the effective verbosity level:

- No flags: `WARNING` level (default)
- `-v`: `INFO` level
- `-vv`: `DEBUG` level
- `-q`: `ERROR` level
- `-qq`: `ERROR` level (same as `-q`)

Example:
```bash
hunterx scan target.com -v   # Info-level logging
hunterx scan target.com -vv  # Debug-level logging
hunterx scan target.com -q   # Error-only logging
```

### Environment Variables

There are no dedicated environment variables for logging configuration.
The log level is derived solely from the `-v` and `-q` flags.

### Configuration File

Logging settings cannot be configured via the `hunterx.yaml` file.
The log level is always determined by the command-line verbosity flags.

## Log Output

By default, HunterX writes logs to:

- **Standard Error (stderr)**: All log messages
- **No file logging**: HunterX does not write logs to a file by default

## Custom Logging Configuration

Advanced users can configure logging programmatically by modifying the logger
before invoking HunterX, or by using the Python logging configuration API
in their own scripts that call HunterX as a library.

## Notes

- Changing the log level does not affect the output of scan results or reports.
- Debug logging (`-vv`) may produce voluminous output and is primarily useful for troubleshooting.
- In quiet mode (`-q`), only errors are displayed, which may suppress useful warnings.
- The timestamp and logger name are not included in the default log format.
- For persistent logs, consider redirecting stderr to a file:
  ```bash
  hunterx scan target.com 2> hunt.log
  ```
