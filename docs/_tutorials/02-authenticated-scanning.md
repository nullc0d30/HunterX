---
layout: default
title: Authenticated Scanning with HunterX
description: >-
  Tutorial on authenticated scanning with HunterX. Covers Basic Auth, Bearer
  Token, Cookie Jar import, and Form Login authentication methods with
  practical examples.
---

# Tutorial: Authenticated Scanning

## Basic Auth

```bash
python hunterx.py scan -u http://example.com/admin \
  -a basic --auth-user admin --auth-pass s3cret
```

## Bearer Token

```bash
python hunterx.py scan -u http://example.com/api \
  -a bearer --auth-token eyJhbGciOiJIUzI1NiIs...
```

## Cookie Jar

Create `cookies.json`:

```json
{
  "cookies": [
    {"name": "session", "value": "abc123", "domain": "example.com"}
  ]
}
```

```bash
python hunterx.py scan -u http://example.com --cookie-file cookies.json
```

## Form Login

HunterX can programmatically log in via HTML forms:

```bash
python hunterx.py scan -u http://example.com \
  -a form --auth-user user --auth-pass pass
```

For custom form fields, use the YAML config:

```yaml
auth:
  method: form
  form:
    url: "http://example.com/login"
    username_field: "email"
    password_field: "passwd"
    username: "user@example.com"
    password: "s3cret"
    extra_fields:
      csrf_token: "token_value"
      remember: "1"
```
