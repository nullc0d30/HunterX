# Tool Readiness, Auto-Provisioning & Integration Integrity

HunterX is a security **orchestration** platform: it plans and drives *external*
security tools (nmap, subfinder, nuclei, ffuf, ...). Before a mission can use a
tool, HunterX must **discover it, validate it, provision it when possible and
verify it** — otherwise a mission would silently do nothing while appearing to
run a security assessment.

The Tool Readiness subsystem owns that lifecycle:

```
HunterX installation
        ↓
Environment discovery
        ↓
Tool inventory
        ↓
Capability validation
        ↓
Missing tool detection
        ↓
Automatic provisioning/install where supported
        ↓
Post-install verification
        ↓
Tool registration
        ↓
Capability availability
        ↓
Mission preflight
        ↓
Tool execution
```

## 0. The installer is a bootstrapper

`install.sh` is an **environment bootstrapper**, not just `pip install`:

```
Detect environment
    ↓
Install HunterX Python package
    ↓
Invoke the canonical Tool Readiness layer (hunterx install / tools install)
    ↓
Discover installed tools / validate executables / identify missing & broken
    ↓
Provision missing tools (trusted static methods only)
    ↓
Configure PATH (current process + future shells, idempotent)
    ↓
Re-discover / verify readiness
    ↓
Report final readiness (COMPLETE / DEGRADED / INCOMPLETE)
```

The canonical tool manifest lives in the Python package
(`hunterx.tools.readiness.manifest`). **`install.sh` never duplicates it**:
external-tool discovery, validation, provisioning and verification are delegated
to the Tool Readiness Service through the CLI. The shell script only handles
environment detection, package installation and PATH management.

```bash
./install.sh                      # full external toolchain (default)
./install.sh --profile recon      # recon toolset
./install.sh --profile minimal    # base environment only
./install.sh --core               # base package + minimal profile
```

Runtimes and package managers are detected, never assumed: `go`/`cargo`/`brew`/
`apt-get`/`pacman`/`dnf`/`choco`/`pipx`/`npm` are used only when actually
present, so the provisioner never attempts unavailable commands. PATH is
updated for the **current process** (install → PATH → verify in the same run)
and persisted idempotently for future shells. The final stage runs
`hunterx tools check` and reports:

- `INSTALLATION COMPLETE` — all required capabilities established;
- `INSTALLATION COMPLETE — DEGRADED` — base established, optional tools missing;
- `INSTALLATION INCOMPLETE` — mandatory capabilities could not be established,
  with the exact missing providers listed (exit code 1).

## 1. HunterX external tool dependencies

HunterX's own Python package is **separate from the external security tools it
integrates**. The Tool Readiness subsystem keeps a machine-readable definition
for every integrated tool:

```text
ToolDefinition
├── name
├── executable
├── aliases
├── version_command
├── required
├── capabilities
├── platform_support
├── installation_methods
└── verification
```

Tool knowledge (purpose, capabilities, arguments, safety) lives in the Tool
Intelligence Platform (TIP) registry. The readiness manifest
(`src/hunterx/tools/readiness/manifest.py`) only adds the discovery and
provisioning facts (binary name, version probe, trusted install methods,
profiles). **There is no second tool registry** — the planner reasons about
capabilities, not hardcoded tool names.

## 2. What `hunterx install` does

`hunterx install [--profile <name>]` establishes the **base HunterX environment**
(or the selected tool profile):

1. Detects the runtime platform (see *Supported platforms*).
2. Registers every tool definition from the TIP + manifest.
3. Discovers which tools are already available (`AVAILABLE` / `MISSING` /
   `BROKEN` / `OUTDATED` / `UNSUPPORTED`).
4. Provisions the selected profile (default `minimal` — in-process adapters;
   no external binaries are downloaded).
5. Reports the readiness summary, per-tool outcomes and the status
   (`complete` / `degraded` / `incomplete`).

It is **idempotent**: running it repeatedly never corrupts the environment —
already-available tools are detected, verified and reused.

## 3. How to check tool readiness

```bash
hunterx tools check
```

Prints a per-tool table:

```text
Tool        Status     Version  Path
----------  ---------  -------  ----------------
nmap        AVAILABLE  7.94     /usr/bin/nmap
httpx       MISSING    -        -
nuclei      MISSING    -        -
sqlmap      AVAILABLE  1.10.8   /home/u/.local/bin/sqlmap
```

and per-capability coverage:

```text
Capability            Level      Status   Providers
--------------------  ---------  -------  ------------
subdomain_enumeration required   MISSING  -
port_discovery        required   READY    nmap
vulnerability_scanning recommended DEGRADED nuclei
```

Use `hunterx tools check --json` for machine-readable output, or
`hunterx tools list` for the pure catalog.

## 4. How missing tools are handled

- **Discovered**: every registered tool is probed (`shutil.which` → absolute
  path → executability check → version probe).
- **Classified**: `tool does not exist` (**MISSING**) is distinguished from
  `tool exists but cannot execute` (**BROKEN**). A binary whose version probe
  output does not match its declared pattern is classified **BROKEN** (this
  rejects same-named unrelated packages, e.g. the Python `httpx` client vs
  ProjectDiscovery's `httpx`).
- **Provisioned**: if a trusted install method exists for the current platform,
  HunterX runs it (see *Automatic provisioning*).
- **Verified**: every install is re-probed before it is declared successful.
- **Reported**: failures are explicit (`PROVISIONING_FAILED`,
  `UNSUPPORTED`), never silent.

### Binary identity

A tool is never classified `AVAILABLE` merely because `which <binary>` returns
a path. The identity probe verifies:

```text
expected executable + expected version signature + expected command behavior
```

If the wrong binary is found (e.g. the Python `httpx` HTTP client shadowing
ProjectDiscovery's `httpx`), the tool is **BROKEN** and provisioning continues.
An unrelated executable is never overwritten blindly.

## 5. Automatic provisioning

Provisioning uses **trusted, static installation methods** declared in the
manifest. Commands are built from static package names/module paths — user or
target input **never** influences an install command.

Supported families:

| Family | Example command | Tools |
| ------ | --------------- | ----- |
| `apt` | `apt-get install -y nmap` | nmap, masscan, whatweb, amass, gobuster, sqlmap, metasploit, ... |
| `brew` | `brew install nmap` | nmap, gitleaks, trufflehog, whatweb, nuclei, ... |
| `go` | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` | subfinder, httpx, nuclei, katana, ffuf, ... |
| `cargo` | `cargo install feroxbuster` | feroxbuster, rustscan, findomain |
| `pip` / `pipx` | `python -m pip install --user sqlmap` | sqlmap, dirsearch, arjun, commix, sstimap, mitmproxy, semgrep, ... |
| `pacman` / `dnf` | `pacman -S --noconfirm nmap` | Arch / Fedora equivalents |
| `choco` | `choco install -y nmap` | nmap, sqlmap, gobuster, masscan, amass, metasploit, gitleaks (Windows) |

Only methods whose runtime/package manager is actually present are used — a
machine without `go` never attempts `go install`. Fallback is automatic: if the
preferred method is unavailable, the next trusted manifest method is tried.
Download URLs are never fabricated and arbitrary sites are never scraped.

Provisioning is **idempotent** — an already-available tool is never
reinstalled (detect → verify → reuse).

```bash
hunterx tools install                    # minimal (base environment)
hunterx tools install --profile recon    # recon toolset
hunterx tools install --profile web      # web assessment toolset
hunterx tools install --profile network  # network scanning toolset
hunterx tools install --profile vulnerability
hunterx tools install --profile full     # complete external toolchain
hunterx tools install nmap ffuf          # explicit tool ids
```

### No blind `pip install`

For Python-based tools, a pip package existing does **not** mean the correct
security tool exists. After installation HunterX verifies the console script
exists, the binary identity is correct and the version is valid (smoke test).
Known collisions (`httpx`, `ghauri`, `sstimap`, `dirsearch`, ...) are handled
by the readiness classification: a placeholder package that installs no
console script reports `PROVISIONING_FAILED`, never `AVAILABLE`.

## 6. Supported platforms

The installer detects the runtime environment:

| Environment | Detection | Package manager |
| ----------- | --------- | --------------- |
| Debian / Ubuntu / Kali / Parrot | `/etc/os-release` | `apt` |
| Arch-based (Arch, Manjaro, ...) | `/etc/os-release` | `pacman` |
| Fedora / RHEL / Rocky / AlmaLinux | `/etc/os-release` | `dnf` |
| macOS | `sys.platform` | `brew` |
| Windows | `sys.platform` | `choco` (best-effort, trusted packages only) |
| WSL | `/proc/version` | inherits Linux manager |
| Docker / container | `/.dockerenv`, `/proc/1/cgroup` | inherits image |

Unsupported environments are reported as `UNSUPPORTED` clearly — never
guessed. Tools without a compatible install method on the current platform
are reported `UNSUPPORTED` rather than installed unsafely.

## 7. Capability-based planning

The mission planner determines required capabilities from the objective,
target type, mission phase, evidence and strategy. Capabilities resolve to
**providers** through the readiness manifest — the same mapping the tool
selection engine uses:

```text
full_security_assessment
        ↓
subdomain_enumeration → subfinder, amass, assetfinder, ...
dns_enumeration       → dnsx, massdns, shuffledns, ...
port_discovery        → nmap, rustscan, naabu, masscan, ...
...
```

If one provider is missing, another may satisfy the capability. `nmap` missing
does **not** block `port_discovery` if `rustscan` is available.

## 8. Mission preflight

Every `hunterx hunt` mission runs a **preflight gate** before execution:

```text
Mission created
     ↓
Required capabilities calculated (from the adaptive plan)
     ↓
Tool readiness checked
     ↓
Missing tools provisioned (when supported)
     ↓
Tools verified
     ↓
Mission execution unlocked
```

- Required capabilities with no available provider → the mission is
  **blocked** with an explicit `status: blocked`, the missing capability names
  and the missing tool ids. It never enters active execution.
- When `auto_provision` is enabled (the default), missing required providers
  are provisioned first; if provisioning succeeds the mission proceeds, if it
  fails the mission blocks with the provisioning failure.

## 9. Degraded mode

Not every missing tool blocks a mission. Capabilities are classified:

```text
required     → must have a provider (blocks the mission if missing)
recommended  → strongly preferred (degrades the mission if missing)
optional     → nice to have (degrades the mission if missing)
```

A mission whose required capabilities are satisfied but whose
recommended/optional providers are missing runs in **degraded** mode:

```text
status: degraded
missing_optional:
  - certificate_enumeration
```

Degraded missions still execute; the reduced coverage is reported, never
silently accepted.

## 10. Integration audit & maturity

`hunterx tools audit` reports the **integration maturity** of every claimed
tool — knowledge and runtime are kept separate:

```text
Tool      Level             Runtime  Available  Missing
--------  ----------------  -------  ---------  ---------
nmap      FULLY_INTEGRATED  YES      no         -
massdns   INSTALLABLE       YES      no         verification
kiterunner DISCOVERABLE     YES      no         installation,verification
```

A tool is **never** considered fully integrated merely because its name appears
in a registry. The audit measures machine-actionable knowledge for every
dimension:

```text
Identity, Capability, Discovery, Installation, Verification, Version,
Commands, Arguments, Invocation, Output, Parser, Platform, Safety
```

and derives a maturity level:

```text
KNOWN → DISCOVERABLE → INSTALLABLE → VERIFIED → INVOKABLE → PARSABLE →
FULLY_INTEGRATED
```

**Tool Knowledge** ("HunterX knows what the tool is and how to operate it") is
distinct from **Tool Runtime State** ("this exact tool is installed and healthy
right now"). A tool is an executable capability only when both are valid. CI
enforces the audit: every claimed tool must be discoverable, the derived level
must match the actual dimensions, and `FULLY_INTEGRATED` requires every
dimension (see
`tests/architecture/test_tool_integration_completeness.py` and
`test_tool_cross_layer_consistency.py`).

Command knowledge is machine-actionable (command, required/optional arguments,
argument types, defaults, output formats, supported modes, target binding):

```text
Capability → Provider → Tool Knowledge → Command Template → Arguments →
Validation → Executable Command
```

## 11. Troubleshooting missing tools

| Symptom | Meaning | Fix |
| ------- | ------- | --- |
| `MISSING` | Binary not on PATH | `hunterx tools install <tool>` or add its directory to PATH |
| `BROKEN` | Binary exists but fails its identity/version probe | Verify it is the correct tool; reinstall it |
| `OUTDATED` | Version below the supported minimum | Upgrade the tool (or `hunterx tools install <tool>`) |
| `UNSUPPORTED` | No trusted install method for this platform | Install manually per the tool's documentation |
| `PROVISIONING_FAILED` | Install ran but verification failed | Inspect the captured `error`/`stderr`; install manually |
| mission `blocked` | A required capability has no provider | `hunterx tools check` to see what is missing, then provision |
| `httpx` shows `BROKEN` | Same-named unrelated package on PATH | Remove the impostor binary or install the real `httpx` |
| `tools audit` shows a low level | Missing knowledge dimensions | The tool is honestly reported; knowledge must be added to reach full integration |

After provisioning, re-run `hunterx tools check` to confirm readiness, then
start the mission again.

---

## Reference

- Source: `src/hunterx/tools/readiness/` (models, platform, manifest,
  definitions, discovery, provisioner, service, preflight, audit, knowledge).
- Manifest: `src/hunterx/tools/readiness/manifest.py` (the trusted static
  inventory; single source of truth — never duplicated in shell).
- Command knowledge: `src/hunterx/tools/readiness/knowledge.py`.
- Composition root: `src/hunterx/platform/assembler.py` wires the readiness
  service into the v7 platform.
- Mission gate: `src/hunterx/application/mission_execution.py`
  (`MissionExecutionService.run`).
- CLI: `hunterx install`, `hunterx tools check`, `hunterx tools install`,
  `hunterx tools audit`.
- Installer: `install.sh` (bootstrapper delegating to the readiness layer).
