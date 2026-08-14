#!/usr/bin/env bash
# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX v7 — AI-Powered Security Orchestration & Intelligence Platform
# Environment Bootstrapper
#
# The installer is an environment bootstrap, not just `pip install`:
#
#     Detect environment
#         ↓
#     Install HunterX Python package
#         ↓
#     Invoke the canonical Tool Readiness layer (hunterx install / tools install)
#         ↓
#     Discover installed tools
#         ↓
#     Validate existing executables / identify missing / broken
#         ↓
#     Provision missing tools (trusted static methods only)
#         ↓
#     Configure PATH (current process + future shells, idempotent)
#         ↓
#     Re-discover / verify readiness
#         ↓
#     Report final readiness (COMPLETE / DEGRADED / INCOMPLETE)
#
# The canonical tool manifest lives in the Python package
# (hunterx.tools.readiness.manifest). This script NEVER duplicates it: external
# tool discovery, validation, provisioning and verification are delegated to the
# Tool Readiness Service through the CLI. `install.sh` only handles environment
# detection and PATH management (the shell-only concerns).
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/nullc0d30/HunterX/main/install.sh | sudo bash
#   curl -sSL https://raw.githubusercontent.com/nullc0d30/HunterX/main/install.sh | bash -s -- --user
#   curl -sSL https://raw.githubusercontent.com/nullc0d30/HunterX/main/install.sh | sudo bash -s -- --all
#   curl -sSL https://raw.githubusercontent.com/nullc0d30/HunterX/main/install.sh | sudo bash -s -- --profile full
#   curl -sSL https://raw.githubusercontent.com/nullc0d30/HunterX/main/install.sh | sudo bash -s -- --uninstall
#   curl -sSL https://raw.githubusercontent.com/nullc0d30/HunterX/main/install.sh | bash -s -- --user --uninstall

set -euo pipefail

INSTALL_DIR="/opt/hunterx"
USER_INSTALL_DIR="${HOME}/.local/share/hunterx"
VENV_DIR=""
BIN_DIR=""
PROJECT_NAME="hunterx"
# PyPI distribution name. The import package, CLI command and Docker image all
# stay "hunterx"; "hunterx" itself is an unrelated project on PyPI, so HunterX
# publishes as "hunterxsec". Used only for the PyPI fallback install below.
PYPI_PACKAGE="hunterxsec"
SYMLINKS=("HunterX" "Hunterx" "hunterX" "HUNTERX")
INSTALL_MODE="system"
DO_UNINSTALL=false
# Optional dependency set installed alongside the core. Default is the full
# v7 platform (REST API + database); --core installs only the base package.
EXTRAS="api,db"
# Tool-readiness installation profile provisioned after the package install.
# Defaults to the full external toolchain; --core uses the minimal profile.
TOOL_PROFILE="full"
REQUIRED_DIRS=("data" "reports" "config")

#: Directories (other than the HunterX bin dir) that provisioned tools land in.
TOOL_PATH_DIRS=(
    "${HOME}/.local/bin"
    "${HOME}/.cargo/bin"
)

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
step()  { echo -e "\n${BLUE}==>${NC} $1"; }

cleanup() {
    local ec=$?
    if [ $ec -ne 0 ] && [ $ec -ne 130 ]; then
        error "Installation failed (exit code $ec). Check messages above."
    fi
    set +e
}
trap cleanup EXIT

have_cmd() { command -v "$1" &>/dev/null; }

# shellcheck disable=SC2120
path_contains() {
    local dir="$1"
    case ":${PATH:-}:" in
        *":${dir}:"*) return 0 ;;
        *) return 1 ;;
    esac
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --user)
                INSTALL_MODE="user"
                shift
                ;;
            --uninstall)
                DO_UNINSTALL=true
                shift
                ;;
            --core)
                EXTRAS=""
                TOOL_PROFILE="minimal"
                shift
                ;;
            --all)
                EXTRAS="all"
                shift
                ;;
            --profile)
                if [[ $# -lt 2 ]]; then
                    error "--profile requires an argument (minimal|recon|web|network|vulnerability|full)"
                    exit 1
                fi
                TOOL_PROFILE="$2"
                shift 2
                ;;
            --help|-h)
                echo "Usage: install.sh [--user] [--core|--all] [--profile <name>] [--uninstall]"
                echo ""
                echo "  --user            Install to user home directory (no root/sudo required)"
                echo "  --core            Install only the core package (minimal tool profile)"
                echo "  --all             Install every optional extra (api, db, report, ai, ...)"
                echo "  --profile <name>  Tool readiness profile to provision (minimal|recon|web|network|vulnerability|full)"
                echo "  --uninstall       Remove HunterX installation"
                exit 0
                ;;
            *)
                shift
                ;;
        esac
    done
}

uninstall_hunterx() {
    step "Uninstalling HunterX"
    local dirs=()
    local bins=()

    if [ "$INSTALL_MODE" = "system" ]; then
        dirs=("/opt/hunterx")
        bins=("/usr/local/bin/${PROJECT_NAME}")
        for link in "${SYMLINKS[@]}"; do
            bins+=("/usr/local/bin/${link}")
        done
    else
        dirs=("${HOME}/.local/share/hunterx")
        bins=("${HOME}/.local/bin/${PROJECT_NAME}")
        for link in "${SYMLINKS[@]}"; do
            bins+=("${HOME}/.local/bin/${link}")
        done
    fi

    for d in "${dirs[@]}"; do
        if [ -d "$d" ]; then
            rm -rf "$d" && info "Removed directory: $d"
        else
            info "Directory not found, skipping: $d"
        fi
    done

    for b in "${bins[@]}"; do
        if [ -f "$b" ] || [ -L "$b" ]; then
            rm -f "$b" && info "Removed: $b"
        else
            info "Not found, skipping: $b"
        fi
    done

    # Remove persistent database env config
    if [ "$INSTALL_MODE" = "system" ]; then
        rm -f /etc/profile.d/hunterx.sh /etc/fish/conf.d/hunterx.fish 2>/dev/null || true
        info "Removed /etc/profile.d/hunterx.sh and fish config."
    else
        for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
            if [ -f "$rc" ]; then
                sed -i "\|export HUNTERX_DATABASE_URL=|d; \|export HUNTERX_DB_URL=|d" "$rc" 2>/dev/null || true
            fi
        done
        if [ -f "$HOME/.config/fish/config.fish" ]; then
            sed -i "\|set -gx HUNTERX_DATABASE_URL |d; \|set -gx HUNTERX_DB_URL |d" "$HOME/.config/fish/config.fish" 2>/dev/null || true
        fi
    fi

    # Clean PATH exports from shell configs
    local cleaned=false
    for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
        if [ -f "$rc" ]; then
            sed -i "\|export PATH=\$PATH:${BIN_DIR%/*}|d" "$rc" 2>/dev/null || true
            cleaned=true
        fi
    done
    if [ -f "$HOME/.config/fish/config.fish" ]; then
        sed -i "\|set -gx PATH \$PATH ${BIN_DIR%/*}|d" "$HOME/.config/fish/config.fish" 2>/dev/null || true
        cleaned=true
    fi

    info "Uninstall complete."
    if $cleaned; then
        warn "Shell config files were modified. You may need to restart your shell or run: hash -r"
    fi
    exit 0
}

detect_distro() {
    step "Detecting Linux distribution"
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO_ID="$ID"
        DISTRO_NAME="$NAME"
        DISTRO_VERSION_ID="${VERSION_ID:-}"
    elif [ -f /etc/debian_version ]; then
        DISTRO_ID="debian"
        DISTRO_NAME="Debian"
    elif [ -f /etc/redhat-release ]; then
        DISTRO_ID="rhel"
        DISTRO_NAME="RedHat"
    elif [ -f /etc/alpine-release ]; then
        DISTRO_ID="alpine"
        DISTRO_NAME="Alpine"
    else
        error "Unsupported or unknown Linux distribution."
        error "Please install Python 3.11+ and pip manually, then run: pip install ."
        exit 1
    fi
    info "Detected: ${DISTRO_NAME} ${DISTRO_VERSION_ID}"

    case "$DISTRO_ID" in
        ubuntu|debian|linuxmint|pop|elementary|raspbian)
            PKG_MANAGER="apt-get"
            PKG_UPDATE="$PKG_MANAGER update"
            PYTHON_PKGS="python3 python3-pip python3-venv"
            INSTALL_CMD="$PKG_MANAGER install -y"
            ;;
        fedora|rhel|centos|rocky|almalinux)
            PKG_MANAGER="dnf"
            if ! have_cmd dnf; then PKG_MANAGER="yum"; fi
            PKG_UPDATE="$PKG_MANAGER check-update || true"
            PYTHON_PKGS="python3 python3-pip python3-venv"
            INSTALL_CMD="$PKG_MANAGER install -y"
            ;;
        arch|manjaro|endeavouros)
            PKG_MANAGER="pacman"
            PKG_UPDATE="$PKG_MANAGER -Sy"
            PYTHON_PKGS="python python-pip"
            INSTALL_CMD="$PKG_MANAGER -S --noconfirm"
            ;;
        alpine)
            PKG_MANAGER="apk"
            PKG_UPDATE="$PKG_MANAGER update"
            PYTHON_PKGS="python3 py3-pip"
            INSTALL_CMD="$PKG_MANAGER add"
            ;;
        opensuse*|suse)
            PKG_MANAGER="zypper"
            PKG_UPDATE="$PKG_MANAGER refresh"
            PYTHON_PKGS="python3 python3-pip python3-venv"
            INSTALL_CMD="$PKG_MANAGER install -y"
            ;;
        *)
            error "Unsupported distribution: ${DISTRO_NAME}. Install Python 3.11+ and pip manually."
            exit 1
            ;;
    esac
    info "Package manager: $PKG_MANAGER"
}

install_system_deps() {
    step "Installing system dependencies"
    if [ "$INSTALL_MODE" = "user" ]; then
        info "User mode: skipping system package installation."
        info "Ensure Python 3.11+ and pip are already installed."
        return
    fi
    if [ "$(id -u)" -eq 0 ]; then
        info "Running as root, installing packages..."
        $PKG_UPDATE >/dev/null 2>&1 || true
        $INSTALL_CMD $PYTHON_PKGS >/dev/null 2>&1 || {
            error "Failed to install system packages. Try: $INSTALL_CMD $PYTHON_PKGS"
            exit 1
        }
    else
        warn "Not running as root. Attempting sudo for package installation..."
        if have_cmd sudo; then
            sudo $PKG_UPDATE >/dev/null 2>&1 || true
            sudo $INSTALL_CMD $PYTHON_PKGS >/dev/null 2>&1 || {
                error "Failed to install system packages via sudo."
                error "Run: sudo $INSTALL_CMD $PYTHON_PKGS"
                exit 1
            }
        else
            warn "sudo not available. Ensure Python 3.11+ and pip are already installed."
        fi
    fi
    info "System dependencies satisfied"
}

check_python() {
    step "Checking Python version"
    local py_cmd=""
    for c in python3 python; do
        if have_cmd "$c"; then
            local ver
            ver=$("$c" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "0")
            local major="${ver%.*}"
            local minor="${ver#*.}"
            if [ "$major" -ge 3 ] && [ "$minor" -ge 11 ]; then
                py_cmd="$c"
                break
            fi
        fi
    done
    if [ -z "$py_cmd" ]; then
        error "Python 3.11+ is required. Please install it first."
        exit 1
    fi
    PYTHON="$py_cmd"
    info "Found: $("$PYTHON" --version)"
}

install_hunterx() {
    step "Installing HunterX"

    if [ "$INSTALL_MODE" = "system" ]; then
        VENV_DIR="${INSTALL_DIR}/venv"
        BIN_DIR="/usr/local/bin"
        if [ -d "$INSTALL_DIR" ]; then
            info "Existing installation found at ${INSTALL_DIR}. Upgrading in place (idempotent)..."
        fi
    else
        VENV_DIR="${USER_INSTALL_DIR}/venv"
        BIN_DIR="${HOME}/.local/bin"
        mkdir -p "$(dirname "$USER_INSTALL_DIR")"
        if [ -d "$USER_INSTALL_DIR" ]; then
            info "Existing installation found at ${USER_INSTALL_DIR}. Upgrading in place (idempotent)..."
        fi
        mkdir -p "$BIN_DIR"
    fi

    mkdir -p "$(dirname "$VENV_DIR")" "$BIN_DIR"
    for dir in "${REQUIRED_DIRS[@]}"; do
        mkdir -p "$(dirname "$VENV_DIR")/${dir}"
    done

    if [ ! -x "${VENV_DIR}/bin/python" ]; then
        info "Creating virtual environment at ${VENV_DIR}"
        "$PYTHON" -m venv "$VENV_DIR"
    else
        info "Virtual environment already present at ${VENV_DIR}"
    fi
    # shellcheck disable=SC1091
    source "${VENV_DIR}/bin/activate"

    pip install --upgrade pip >/dev/null 2>&1 || true

    local src_dir
    src_dir="$(cd "$(dirname "$0")" && pwd)"
    if [ -f "${src_dir}/pyproject.toml" ]; then
        info "Installing from local source: ${src_dir}"
        if [ -n "$EXTRAS" ]; then
            pip install --no-cache-dir --upgrade "${src_dir}[${EXTRAS}]" >/dev/null 2>&1 || {
                error "pip install from local source failed."
                exit 1
            }
        else
            pip install --no-cache-dir --upgrade "$src_dir" >/dev/null 2>&1 || {
                error "pip install from local source failed."
                exit 1
            }
        fi
    else
        info "Local source not found. Installing from PyPI..."
        if [ -n "$EXTRAS" ]; then
            pip install --no-cache-dir --upgrade "${PYPI_PACKAGE}[${EXTRAS}]" >/dev/null 2>&1 || {
                error "pip install from PyPI failed."
                exit 1
            }
        else
            pip install --no-cache-dir --upgrade "$PYPI_PACKAGE" >/dev/null 2>&1 || {
                error "pip install from PyPI failed."
                exit 1
            }
        fi
    fi

    deactivate
    info "HunterX installed into virtual environment"
}

initialize_database() {
    step "Initializing database (Alembic migrations)"

    local src_dir
    src_dir="$(cd "$(dirname "$0")" && pwd)"
    local config_arg=""
    if [ -f "${src_dir}/alembic.ini" ]; then
        config_arg="-c ${src_dir}/alembic.ini"
    fi

    if [ -x "${VENV_DIR}/bin/python" ]; then
        info "Running database migrations via the installed package..."
        (
            # Alembic resolves script_location relative to the working
            # directory, so run from the source tree when present.
            if [ -d "${src_dir}/alembic" ]; then
                cd "$src_dir"
            fi
            # Alembic reads the URL from HUNTERX_DB_URL or alembic.ini; the
            # config ships with the source tree (alembic.ini + alembic/versions).
            # On PyPI-only installs without a bundled config the step is skipped
            # gracefully — the CLI creates tables on demand.
            "${VENV_DIR}/bin/python" -m alembic ${config_arg} upgrade head 2>&1 || {
                warn "Alembic migration step did not complete. This is not fatal;"
                warn "HunterX creates tables on demand. Run: alembic upgrade head"
            }
        )
    else
        warn "Package binary not found; skipping database initialization."
    fi
}

install_executable() {
    step "Installing executable and symlinks"

    mkdir -p "$BIN_DIR"
    local venv_bin="${VENV_DIR}/bin"
    local main_bin="${BIN_DIR}/${PROJECT_NAME}"

    if [ -f "${venv_bin}/${PROJECT_NAME}" ]; then
        info "Creating symlink: ${main_bin} -> ${venv_bin}/${PROJECT_NAME}"
        ln -sf "${venv_bin}/${PROJECT_NAME}" "$main_bin"
    else
        local wrapper="${main_bin}"
        info "Creating wrapper script at ${wrapper}"
        cat > "$wrapper" << WRAPEOF
#!/usr/bin/env bash
exec ${VENV_DIR}/bin/python -m hunterx "\$@"
WRAPEOF
        chmod +x "$wrapper"
    fi

    info "Creating case-variant symlinks..."
    local target
    for link in "${SYMLINKS[@]}"; do
        target="${BIN_DIR}/${link}"
        if [ -f "$target" ] || [ -L "$target" ]; then
            rm -f "$target"
        fi
        ln -s "$PROJECT_NAME" "$target"
        info "  ${target} -> ${PROJECT_NAME}"
    done

    info "Executable installed at ${main_bin}"
}

append_once() {
    local file="$1"
    local line="$2"
    if [ -f "$file" ]; then
        if ! grep -qF -- "$line" "$file" 2>/dev/null; then
            echo "$line" >> "$file"
        fi
    fi
}

configure_database_env() {
    step "Configuring persistent database path"

    local data_dir
    data_dir="$(dirname "$VENV_DIR")/data"
    mkdir -p "$data_dir"

    # Absolute SQLAlchemy URL: the leading slash of $data_dir yields the
    # documented sqlite:////abs/path form. Keeps the CLI from falling back to
    # a CWD-relative ./hunterx.db.
    local db_url
    db_url="sqlite:///${data_dir}/hunterx.db"

    # System installs run as root but are normally invoked via sudo; hand the
    # runtime data directory to the real user so a subsequent non-root
    # `hunterx` run can write the DB. Otherwise SQLite fails with
    # "attempt to write a readonly database".
    if [ "$INSTALL_MODE" = "system" ] && [ -n "${SUDO_USER:-}" ]; then
        chown -R "$SUDO_USER" "$data_dir" 2>/dev/null || true
    fi

    export HUNTERX_DATABASE_URL="$db_url"
    export HUNTERX_DB_URL="$db_url"
    info "Database URL: ${db_url}"

    if [ "$INSTALL_MODE" = "system" ]; then
        if [ "$(id -u)" -eq 0 ]; then
            local profile="/etc/profile.d/hunterx.sh"
            local fish_conf="/etc/fish/conf.d/hunterx.fish"
            mkdir -p "$(dirname "$profile")" "$(dirname "$fish_conf")"
            cat > "$profile" << EOF
# HunterX persistent state (managed by install.sh)
export HUNTERX_DATABASE_URL='${db_url}'
export HUNTERX_DB_URL='${db_url}'
EOF
            cat > "$fish_conf" << EOF
# HunterX persistent state (managed by install.sh)
set -gx HUNTERX_DATABASE_URL '${db_url}'
set -gx HUNTERX_DB_URL '${db_url}'
EOF
            info "Wrote ${profile} and ${fish_conf}"
        else
            warn "Not running as root; skipping /etc/profile.d export."
            warn "Set HUNTERX_DATABASE_URL=${db_url} manually or rerun as root."
        fi
    else
        append_once "$HOME/.bashrc" "export HUNTERX_DATABASE_URL='${db_url}'"
        append_once "$HOME/.bashrc" "export HUNTERX_DB_URL='${db_url}'"
        append_once "$HOME/.zshrc" "export HUNTERX_DATABASE_URL='${db_url}'"
        append_once "$HOME/.zshrc" "export HUNTERX_DB_URL='${db_url}'"
        local fish_cfg="$HOME/.config/fish/config.fish"
        mkdir -p "$(dirname "$fish_cfg")"
        append_once "$fish_cfg" "set -gx HUNTERX_DATABASE_URL '${db_url}'"
        append_once "$fish_cfg" "set -gx HUNTERX_DB_URL '${db_url}'"
        info "Exported HUNTERX_DATABASE_URL in shell config files."
    fi
}

# ---------------------------------------------------------------------------
# Environment detection (shell-only concerns)
# ---------------------------------------------------------------------------

detect_environment() {
    step "Detecting environment"

    local os_name arch
    os_name="$(uname -s 2>/dev/null || echo 'unknown')"
    arch="$(uname -m 2>/dev/null || echo 'unknown')"
    info "OS: ${os_name} | Architecture: ${arch}"

    # Shell
    if [ -n "${BASH_VERSION:-}" ]; then
        DETECTED_SHELL="bash"
    elif [ -n "${ZSH_VERSION:-}" ]; then
        DETECTED_SHELL="zsh"
    else
        DETECTED_SHELL="posix"
    fi
    info "Shell: ${DETECTED_SHELL}"

    # Package managers & runtimes (only report what actually exists)
    local present=""
    for cmd in python3 python pip pipx go cargo npm brew apt-get pacman dnf choco jq; do
        if have_cmd "$cmd"; then
            present="${present}${present:+, }${cmd}"
        fi
    done
    if [ -n "$present" ]; then
        info "Available tools/package managers: ${present}"
    else
        warn "No known package managers or language runtimes detected."
    fi
}

# ---------------------------------------------------------------------------
# PATH management (idempotent; current process + future shells)
# ---------------------------------------------------------------------------

collect_tool_paths() {
    # HunterX user executable directory + the runtimes provisioned tools land in.
    TOOL_PATH_DIRS=(
        "${BIN_DIR:-${HOME}/.local/bin}"
        "${HOME}/.local/bin"
        "${HOME}/.cargo/bin"
    )
    if have_cmd go; then
        local gobin gopath
        gobin="$(go env GOBIN 2>/dev/null || true)"
        gopath="$(go env GOPATH 2>/dev/null || true)"
        if [ -n "$gobin" ] && [ "$gobin" != "" ]; then
            TOOL_PATH_DIRS+=("$gobin")
        fi
        if [ -n "$gopath" ]; then
            TOOL_PATH_DIRS+=("${gopath}/bin")
        fi
    fi
    # Python user script directory (Windows/MSYS style when APPDATA is set).
    if [ -n "${APPDATA:-}" ]; then
        for d in "${APPDATA}"/Python/Python*/Scripts; do
            [ -d "$d" ] && TOOL_PATH_DIRS+=("$d")
        done
    fi
    # Deduplicate
    local seen=""
    local filtered=()
    for d in "${TOOL_PATH_DIRS[@]}"; do
        case ":$seen:" in
            *":$d:"*) ;;
            *) filtered+=("$d"); seen="$seen:$d" ;;
        esac
    done
    TOOL_PATH_DIRS=("${filtered[@]}")
}

ensure_path_for_current_process() {
    local added=()
    for d in "${TOOL_PATH_DIRS[@]}"; do
        [ -d "$d" ] || continue
        if ! path_contains "$d"; then
            export PATH="$d:${PATH}"
            added+=("$d")
        fi
    done
    if [ "${#added[@]}" -gt 0 ]; then
        info "Exported into current PATH: ${added[*]}"
    fi
}

persist_path_for_shells() {
    local line
    for d in "${TOOL_PATH_DIRS[@]}"; do
        [ -d "$d" ] || continue
        if path_contains "$d"; then
            continue
        fi
        case "$DETECTED_SHELL" in
            bash)
                line="export PATH=\"\$PATH:${d}\""
                append_once "$HOME/.bashrc" "$line"
                [ -f "$HOME/.profile" ] && append_once "$HOME/.profile" "$line"
                ;;
            zsh)
                line="export PATH=\"\$PATH:${d}\""
                append_once "$HOME/.zshrc" "$line"
                [ -f "$HOME/.profile" ] && append_once "$HOME/.profile" "$line"
                ;;
            *)
                line="export PATH=\"\$PATH:${d}\""
                [ -f "$HOME/.profile" ] && append_once "$HOME/.profile" "$line"
                ;;
        esac
    done
    info "PATH configuration persisted to shell config files (idempotent)."
}

# ---------------------------------------------------------------------------
# Tool readiness bootstrap (delegates to the canonical Python readiness layer)
# ---------------------------------------------------------------------------

run_hunterx() {
    # Prefer the just-installed binary; fall back to PATH.
    local hx="${BIN_DIR}/${PROJECT_NAME}"
    if [ -x "$hx" ]; then
        "$hx" "$@"
    else
        "${PROJECT_NAME}" "$@"
    fi
}

bootstrap_toolchain() {
    step "Bootstrap: establishing the base HunterX environment"
    if ! run_hunterx install --profile minimal; then
        error "hunterx install (base environment) failed."
        return 1
    fi

    if [ "$TOOL_PROFILE" != "minimal" ]; then
        step "Bootstrap: provisioning tool profile '${TOOL_PROFILE}'"
        if ! run_hunterx tools install --profile "$TOOL_PROFILE"; then
            warn "hunterx tools install --profile ${TOOL_PROFILE} reported failures."
        fi
    fi

    # Re-export PATH so the current process sees freshly provisioned binaries,
    # then re-verify immediately (install → PATH → verify in the same run).
    collect_tool_paths
    ensure_path_for_current_process
    return 0
}

final_readiness_report() {
    step "Final readiness verification (hunterx tools check)"

    local json_file="${TMPDIR:-/tmp}/hunterx_readiness.json"
    if ! run_hunterx tools check --json > "$json_file" 2>/dev/null; then
        warn "hunterx tools check failed; showing the text report instead."
        run_hunterx tools check || true
        return 1
    fi

    local py_interp="${VENV_DIR}/bin/python"
    [ -x "$py_interp" ] || py_interp="$PYTHON"

    "$py_interp" - "$TOOL_PROFILE" "$json_file" <<'PYEOF'
import json
import sys

profile, json_file = sys.argv[1], sys.argv[2]
with open(json_file, encoding="utf-8") as handle:
    data = json.load(handle)

summary = data.get("summary", {})
capabilities = data.get("capabilities", [])
platform = data.get("platform", {})

available = summary.get("available", 0)
missing = summary.get("missing", 0)
broken = summary.get("broken", 0)
outdated = summary.get("outdated", 0)
unsupported = summary.get("unsupported", 0)

print()
print("HunterX installation complete.")
print()
print("Platform:", f"{platform.get('os')} / {platform.get('distro') or platform.get('package_manager')}")
print("Tool readiness:")
print(f"    AVAILABLE:   {available}")
print(f"    MISSING:     {missing}")
print(f"    BROKEN:      {broken}")
print(f"    OUTDATED:    {outdated}")
print(f"    UNSUPPORTED: {unsupported}")
print()
print("Capability coverage:")
for cap in capabilities:
    print(f"    {cap['capability']:<28} {cap['status'].upper()}")
print()

if profile == "minimal":
    # The minimal profile intentionally provisions no external tools; the base
    # environment is complete when its in-process capabilities are available.
    base_missing = [
        c for c in capabilities
        if c.get("capability") in ("proof_validation", "replay") and c.get("status") != "ready"
    ]
    if base_missing:
        print("INSTALLATION INCOMPLETE")
        for c in base_missing:
            print(f"    - {c['capability']}: providers missing ({', '.join(c.get('missing', ()))})")
        sys.exit(1)
    print("INSTALLATION COMPLETE")
    sys.exit(0)

required_missing = [c for c in capabilities if c.get("level") == "required" and c.get("status") != "ready"]
optional_missing = [c for c in capabilities if c.get("level") != "required" and c.get("status") != "ready"]

if required_missing:
    print("INSTALLATION INCOMPLETE")
    print("Mandatory capabilities could not be established:")
    for c in required_missing:
        print(f"    - {c['capability']}: providers missing ({', '.join(c.get('missing', ()))})")
    sys.exit(1)
elif optional_missing:
    print("INSTALLATION COMPLETE — DEGRADED")
    print("Optional capabilities missing (mission runs with reduced coverage):")
    for c in optional_missing:
        print(f"    - {c['capability']}")
    sys.exit(0)
else:
    print("INSTALLATION COMPLETE")
    sys.exit(0)
PYEOF
}

# ---------------------------------------------------------------------------

add_to_path() {
    step "Verifying PATH"
    collect_tool_paths
    ensure_path_for_current_process
    persist_path_for_shells

    if ! path_contains "$BIN_DIR"; then
        export PATH="${BIN_DIR}:${PATH}"
    fi
    info "PATH OK"
}

verify_installation() {
    step "Verifying installation"
    local errors=0

    echo ""
    if have_cmd hunterx || [ -x "${BIN_DIR}/${PROJECT_NAME}" ]; then
        info "1/6: hunterx version"
        run_hunterx version || { error "FAILED"; errors=$((errors+1)); }
        info "2/6: hunterx help"
        run_hunterx help >/dev/null 2>&1 && echo "  (help rendered OK)" || { error "FAILED"; errors=$((errors+1)); }
        info "3/6: hunterx config"
        run_hunterx config >/dev/null 2>&1 && echo "  (config resolved OK)" || { error "FAILED"; errors=$((errors+1)); }
        info "4/6: hunterx platform"
        run_hunterx platform >/dev/null 2>&1 && echo "  (platform composition OK)" || { error "FAILED"; errors=$((errors+1)); }
        info "5/6: hunterx tools list"
        run_hunterx tools list >/dev/null 2>&1 && echo "  (toolchain catalog OK)" || {
            warn "Toolchain catalog did not render. This is not fatal."
        }
        info "6/6: hunterx tools check"
        run_hunterx tools check >/dev/null 2>&1 && echo "  (readiness report OK)" || {
            warn "Readiness report did not render. Inspect output above."
        }
    else
        error "1/6: hunterx command not found on PATH"
        errors=$((errors+1))
    fi

    info "Verifying symlinks..."
    local all_ok=true
    for link in "${PROJECT_NAME}" "${SYMLINKS[@]}"; do
        local lp="${BIN_DIR}/${link}"
        if [ -L "$lp" ] || [ -f "$lp" ]; then
            if [ "$link" = "$PROJECT_NAME" ]; then
                if "$lp" --version >/dev/null 2>&1; then
                    info "  ${lp} OK"
                else
                    warn "  ${lp} exists but may not work"
                fi
            else
            local resolved
            resolved=$(readlink -f "$lp" 2>/dev/null || readlink "$lp" 2>/dev/null || stat -c "%N" "$lp" 2>/dev/null || echo "symlink")
                info "  ${lp} -> ${resolved}"
            fi
        else
            warn "  ${lp} missing"
            all_ok=false
        fi
    done

    echo ""
    if [ "$errors" -eq 0 ]; then
        info "All checks passed! HunterX is ready to use."
    else
        warn "${errors} check(s) failed. Review output above."
    fi
}

show_banner() {
    echo ""
    echo "  _   _             _             __  __"
    echo " | | | |_   _ _ __ | |_ ___ _ __  \ \/ /"
    echo " | |_| | | | | '_ \| __/ _ \ '__|  \  /"
    echo " |  _  | |_| | | | | ||  __/ |     /  \\"
    echo " |_| |_|\__,_|_| |_|\__\___|_|    /_/\_\\"
    echo " HunterX v7 -- AI-Powered Security Orchestration & Intelligence Platform"
    echo ""
}

main() {
    parse_args "$@"

    if $DO_UNINSTALL; then
        show_banner
        info "HunterX Uninstaller"
        echo ""
        uninstall_hunterx
        # uninstall_hunterx calls exit
    fi

    show_banner
    info "HunterX Environment Bootstrapper (${INSTALL_MODE} mode, profile: ${TOOL_PROFILE})"
    echo ""

    if [ "$INSTALL_MODE" = "system" ] && [ "$(id -u)" -ne 0 ]; then
        warn "System-wide installation recommended as root."
        warn "Run with --user for user-local installation, or prefix with sudo."
    fi

    detect_distro
    install_system_deps
    check_python
    detect_environment
    install_hunterx
    install_executable
    configure_database_env
    initialize_database
    add_to_path
    verify_installation

    # Tool readiness bootstrap + final verification.
    bootstrap_toolchain
    final_readiness_report
    local readiness_rc=$?
    if [ "$readiness_rc" -ne 0 ]; then
        error "Tool readiness verification reported mandatory capability failures."
        error "Review the report above and run: hunterx tools check / hunterx tools install --profile ${TOOL_PROFILE}"
        exit "$readiness_rc"
    fi

    echo ""
    info "Installation complete!"
    echo ""
    echo "  Quick start:  hunterx help"
    echo "  Mission:      hunterx mission create <objective> <target>"
    echo "  Hunt:         hunterx hunt <objective> <target>"
    echo "  Toolchain:    hunterx tools list"
    echo "  Readiness:    hunterx tools check"
    echo "  Config:       hunterx config"
    echo "  Version:      hunterx version"
    echo "  Platform:     hunterx platform"
    echo "  Database:     HUNTERX_DATABASE_URL=${HUNTERX_DATABASE_URL:-sqlite:///hunterx.db}"
    echo ""
    if [ "$INSTALL_MODE" = "system" ] && [ -n "${SUDO_USER:-}" ]; then
        echo "  Note: persistent data in $(dirname "$VENV_DIR")/data is owned by ${SUDO_USER};"
        echo "        run hunterx as ${SUDO_USER} (not root) to keep the database writable."
        echo ""
    fi
    echo "  Responsible use: HunterX is an authorized cybersecurity testing and"
    echo "  research platform. Obtain authorization before testing any system."
    echo ""
    if [ "$INSTALL_MODE" = "system" ]; then
        echo "  Uninstall:    sudo bash $0 --uninstall"
    else
        echo "  Uninstall:    bash $0 --user --uninstall"
    fi
    echo ""
}

main "$@"
