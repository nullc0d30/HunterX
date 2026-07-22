---
layout: default
title: Operator Profiles — HunterX
description: >-
  HunterX operator profiles define behavioral constraints for the scanner.
  Internal, Bounty, Gov, and Custom profiles with request limits, rate
  limiting, destructive payload allowance, and passive-mode defaults.
---

# Operator Profiles

HunterX uses operator profiles to enforce safety constraints. Each profile sets defaults for rate limiting, maximum requests, destructive payload allowance, and scan mode.

```
┌──────────────────────────────────────────────────────────────┐
│                    Operator Profiles                         │
├────────────┬──────────┬──────────┬──────────┬───────────────┤
│  Setting   │ Internal │  Bounty  │   Gov    │    Custom     │
├────────────┼──────────┼──────────┼──────────┼───────────────┤
│ Max Reqs   │ Unlimited│   500    │   100    │  User-defined │
│ Rate Limit │ 500/s    │  10/s    │   5/s    │  User-defined │
│ Destructive│ Yes      │   No     │   No     │  User-defined │
│ Passive    │ No       │   No     │   Yes    │  User-defined │
└────────────┴──────────┴──────────┴──────────┴───────────────┘
```

## Internal Profile

The **Internal** profile is designed for authorized internal penetration tests where the operator has full legal authorization to use any payload type.

- **Max Requests**: Unlimited
- **Rate Limit**: 500 requests/second
- **Destructive Payloads**: Allowed
- **Passive-Only**: Off
- **Use Case**: Internal pentests, Red Team exercises on owned infrastructure

## Bounty Profile

The **Bounty** profile is designed for bug bounty hunting on third-party programs. It restricts request volume and disables destructive payloads.

- **Max Requests**: 500
- **Rate Limit**: 10 requests/second
- **Destructive Payloads**: Blocked
- **Passive-Only**: Off
- **Use Case**: Bug bounty programs, responsible disclosure on external targets

## Gov Profile

The **Gov** profile is designed for extremely sensitive government or critical infrastructure testing where even minimal impact is unacceptable.

- **Max Requests**: 100
- **Rate Limit**: 5 requests/second
- **Destructive Payloads**: Blocked
- **Passive-Only**: On (by default)
- **Use Case**: Government-mandated assessments, critical infrastructure, compliance-driven testing

## Custom Profile

Create a custom profile in `hunterx.yaml`:

```yaml
profile:
  name: custom
  max_requests: 250
  max_rps: 25
  allow_destructive: false
  passive_mode: false
```

Custom profiles override all defaults and are not shown in legal banners or `--help`.

## Profile Selection

Select a profile via:
- CLI: `python hunterx.py scan -u http://example.com -p bounty`
- Config: `profile: name: bounty` in `hunterx.yaml`
- Env: `HX_PROFILE=bounty`

## Enforcement

- Profiles are enforced at scan initialization (not per-request)
- Max request count is a hard stop — the scan will not exceed it
- Destructive payload blocklist is always active regardless of profile
