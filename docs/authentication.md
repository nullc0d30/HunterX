---
layout: default
title: Authentication Modes — HunterX
description: >-
  HunterX authentication configuration: Basic Auth, Bearer Token, Cookie Jar,
  and Form Login. CLI flags, YAML config, and environment variable setup for
  authenticated vulnerability scanning.
---

# Authentication

HunterX supports four authentication modes for scanning authenticated targets.

## Basic Auth

```bash
python hunterx.py -u http://example.com -a basic --username admin --password s3cret
```

YAML:
```yaml
auth:
  method: basic
  basic:
    username: admin
    password: s3cret
```

## Bearer Token

```bash
python hunterx.py -u http://example.com -a bearer --token eyJhbGciOi...
```

YAML:
```yaml
auth:
  method: bearer
  bearer:
    token: eyJhbGciOi...
```

## Cookie Jar

Load cookies from a JSON file:

```bash
python hunterx.py -u http://example.com --cookie-file cookies.json
```

YAML:
```yaml
auth:
  method: cookie
  cookie:
    file: cookies.json
```

Cookie JSON format:
```json
{
  "cookies": [
    {"name": "session", "value": "abc123", "domain": "example.com"}
  ]
}
```

## Form Login

Programmatic form-based login:

```yaml
auth:
  method: form
  form:
    url: "http://example.com/login"
    username_field: "username"
    password_field: "password"
    username: "user"
    password: "pass"
    extra_fields:
      csrf_token: "..."   # optional
```

## Environment Variables

```bash
export HX_AUTH_METHOD=basic
export HX_AUTH_USER=admin
export HX_AUTH_PASS=s3cret
```

## Auth Header Applied

All subsequent requests after authentication carry the credential, ensuring the scanner operates within the authenticated session.
