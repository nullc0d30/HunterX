# Supported Platforms

HunterX is tested and supported on the following platforms.

---

## Operating Systems

| OS | Status | Notes |
|---|---|---|
| **Linux (x86_64)** | ✅ Fully supported | Primary target platform |
| **Linux (aarch64/arm64)** | ✅ Fully supported | Including Raspberry Pi 4/5 |
| **macOS (Intel)** | ✅ Supported | Tested on macOS 14+ |
| **macOS (Apple Silicon)** | ✅ Supported | Native ARM support |
| **Windows (native)** | ⚠️ Experimental | Limited testing, WSL recommended |
| **Windows (WSL2)** | ✅ Supported | Run under Ubuntu/Debian WSL |

---

## Linux Distributions

| Distribution | Status | Notes |
|---|---|---|
| **Ubuntu 22.04 LTS** | ✅ Fully supported | Primary CI target |
| **Ubuntu 24.04 LTS** | ✅ Fully supported | |
| **Debian 12** | ✅ Fully supported | |
| **Fedora 39+** | ✅ Supported | |
| **Arch Linux** | ✅ Supported | |
| **Alpine Linux 3.19+** | ✅ Supported | Docker image base |
| **openSUSE Tumbleweed** | ✅ Supported | |
| **RHEL 9 / Rocky Linux 9** | ✅ Supported | |

---

## Python Versions

| Version | Status |
|---|---|
| **3.11** | ✅ Fully supported (minimum) |
| **3.12** | ✅ Fully supported |
| **3.13** | ✅ Fully supported |

---

## Docker

| Platform | Status |
|---|---|
| **linux/amd64** | ✅ Tested in CI |
| **linux/arm64** | ✅ Tested in CI |
| **Docker Compose** | ✅ Supported |

---

## Browser Support (optional feature)

| Browser | Status |
|---|---|
| **Chromium** | ✅ Supported (via Playwright) |
| **Firefox** | ✅ Supported (via Playwright) |

---

## AI Providers (optional)

| Provider | Status |
|---|---|
| **Ollama** (local) | ✅ Fully supported |
| **OpenAI** (GPT-4, GPT-4o) | ✅ Fully supported |
| **Anthropic** (Claude) | 🔄 In development |
| **Google Gemini** | 🔄 In development |
| **AWS Bedrock** | 🔄 In development |
| **Azure OpenAI** | 🔄 In development |

---

## Unsupported Platforms

- 32-bit architectures (i686, armv7)
- BSD variants (FreeBSD, OpenBSD)
- Solaris / illumos
- Embedded Linux without Python 3.11+
