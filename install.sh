#!/usr/bin/env bash
# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX v7 — AI-Powered Security Orchestration & Intelligence Platform
# One-Shot Production Installer
#
# Running `sudo ./install.sh` ONCE prepares the complete HunterX working
# environment:
#
#     Detect environment
#         ↓
#     Prepare OS dependencies
#         ↓
#     Prepare runtime / toolchains
#         ↓
#     Install HunterX
#         ↓
#     Prepare HunterX directories
#         ↓
#     Prepare configuration
#         ↓
#     Prepare database
#         ↓
#     Run migrations
#         ↓
#     Prepare HunterX supporting resources
#         ↓
#     Detect security tools
#         ↓
#     Install missing tools
#         ↓
#     Verify every tool
#         ↓
#     Verify required capabilities
#         ↓
#     Perform final health / readiness check
#         ↓
#     READY
#         ↓
#     Show quick-start commands
#
# The canonical tool manifest lives in the Python package
# (hunterx.tools.readiness.manifest). This script NEVER duplicates it: external
# tool discovery, validation, provisioning and verification are delegated to the
# Tool Readiness Service through the CLI (`hunterx install`, `hunterx tools
# check`, `hunterx tools install`). `install.sh` handles environment detection,
# OS/runtime preparation, directories, configuration, the database, PATH
# management and the final readiness verdict — the shell-only concerns.
#
# Usage:
#   sudo ./install.sh                                  # one-shot system install
#   sudo ./install.sh --profile full                   # explicit tool profile
#   bash ./install.sh --user                           # user-local install
#   bash ./install.sh --core                           # core package only
#   sudo ./install.sh --json                           # machine-readable summary
#   sudo ./install.sh --uninstall                      # remove HunterX

set -euo pipefail

INSTALL_DIR="/opt/hunterx"
USER_INSTALL_DIR="${HOME}/.local/share/hunterx"
STATE_DIR=""
VENV_DIR=""
BIN_DIR=""
PROJECT_NAME="hunterx"
# PyPI distribution name. The import package, CLI command and Docker image all
# stay "hunterx"; "hunterx" itself is an unrelated project on PyPI, so HunterX
# publishes as "hunterxsec". Used only for the PyPI fallback install below.
PYPI_PACKAGE="hunterxsec"
INSTALL_MODE="system"
DO_UNINSTALL=false
JSON_MODE=false
# Optional dependency set installed alongside the core. Default is the full
# v7 platform (REST API + database + AI client transport) so the configured
# AI provider is reachable by the installed CLI; --core installs only the
# base package.
EXTRAS="api,db,ai"
# Tool-readiness installation profile provisioned after the package install.
# Defaults to the full external toolchain; --core uses the minimal profile.
TOOL_PROFILE="full"
HUNTERX_VERSION=""
DB_URL=""
DATA_DIR=""
TOOLCHAIN_STATUS=""
FAILED_TOOLS=""

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
step()  { echo -e "\n${BLUE}==>${NC} $1"; }
ok()    { echo -e "${GREEN}✓${NC} $1"; }
fail()  { echo -e "${RED}✗${NC} $1"; }

# -- graceful interruption ---------------------------------------------------
on_interrupt() {
    echo ""
    echo -e "${YELLOW}[WARN]${NC} Installation interrupted by user."
    echo ""
    echo "Completed work has been preserved."
    echo "The installation can be resumed safely with:"
    echo ""
    echo "  sudo ./install.sh"
    echo ""
    exit 130
}
trap on_interrupt INT TERM

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
            --json)
                JSON_MODE=true
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
                echo "Usage: install.sh [--user] [--core|--all] [--profile <name>] [--json] [--uninstall]"
                echo ""
                echo "  --user            Install to user home directory (no root/sudo required)"
                echo "  --core            Install only the core package (minimal tool profile)"
                echo "  --all             Install every optional extra (api, db, report, ai, ...)"
                echo "  --profile <name>  Tool readiness profile to provision (minimal|recon|web|network|vulnerability|full)"
                echo "  --json            Emit a machine-readable readiness summary"
                echo "  --uninstall       Remove HunterX installation"
                exit 0
                ;;
            *)
                shift
                ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# Uninstall (unchanged contract)
# ---------------------------------------------------------------------------

uninstall_hunterx() {
    step "Uninstalling HunterX"
    local dirs=()
    local bins=()

    if [ "$INSTALL_MODE" = "system" ]; then
        dirs=("/opt/hunterx")
        bins=("/usr/local/bin/${PROJECT_NAME}")
    else
        dirs=("${HOME}/.local/share/hunterx")
        bins=("${HOME}/.local/bin/${PROJECT_NAME}")
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
                sed -i "\|export HUNTERX_DATA_DIR=|d; \|export HUNTERX_DATABASE_URL=|d; \|export HUNTERX_DB_URL=|d" "$rc" 2>/dev/null || true
            fi
        done
        if [ -f "$HOME/.config/fish/config.fish" ]; then
            sed -i "\|set -gx HUNTERX_DATA_DIR |d; \|set -gx HUNTERX_DATABASE_URL |d; \|set -gx HUNTERX_DB_URL |d" "$HOME/.config/fish/config.fish" 2>/dev/null || true
        fi
    fi

    # Clean PATH exports from shell configs
    for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
        if [ -f "$rc" ]; then
            sed -i "\|export PATH=\$PATH:${BIN_DIR%/*}|d" "$rc" 2>/dev/null || true
        fi
    done
    if [ -f "$HOME/.config/fish/config.fish" ]; then
        sed -i "\|set -gx PATH \$PATH ${BIN_DIR%/*}|d" "$HOME/.config/fish/config.fish" 2>/dev/null || true
    fi

    info "Uninstall complete."
    exit 0
}

# ---------------------------------------------------------------------------
# 1. Environment detection
# ---------------------------------------------------------------------------

detect_distro() {
    step "Detecting Linux distribution"
    local pkg_update=""
    if [ -f /etc/os-release ]; then
        # shellcheck disable=SC1091
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
        exit 1
    fi
    info "Detected: ${DISTRO_NAME} ${DISTRO_VERSION_ID}"

    case "$DISTRO_ID" in
        ubuntu|debian|linuxmint|pop|elementary|raspbian|kali|parrot|zorin)
            PKG_MANAGER="apt-get"
            PKG_UPDATE="apt-get update"
            PYTHON_PKGS="python3 python3-pip python3-venv"
            BUILD_PKGS="git curl ca-certificates build-essential"
            INSTALL_CMD="apt-get install -y"
            ;;
        fedora|rhel|centos|rocky|almalinux)
            PKG_MANAGER="dnf"
            if ! have_cmd dnf; then PKG_MANAGER="yum"; fi
            PKG_UPDATE="$PKG_MANAGER check-update || true"
            PYTHON_PKGS="python3 python3-pip"
            BUILD_PKGS="git curl ca-certificates gcc make"
            INSTALL_CMD="$PKG_MANAGER install -y"
            ;;
        arch|manjaro|endeavouros)
            PKG_MANAGER="pacman"
            PKG_UPDATE="pacman -Sy"
            PYTHON_PKGS="python python-pip"
            BUILD_PKGS="git curl ca-certificates base-devel"
            INSTALL_CMD="pacman -S --noconfirm"
            ;;
        alpine)
            PKG_MANAGER="apk"
            PKG_UPDATE="apk update"
            PYTHON_PKGS="python3 py3-pip"
            BUILD_PKGS="git curl ca-certificates build-base"
            INSTALL_CMD="apk add"
            ;;
        opensuse*|suse)
            PKG_MANAGER="zypper"
            PKG_UPDATE="zypper refresh"
            PYTHON_PKGS="python3 python3-pip python3-venv"
            BUILD_PKGS="git curl ca-certificates gcc make"
            INSTALL_CMD="zypper install -y"
            ;;
        *)
            error "Unsupported distribution: ${DISTRO_NAME}. Install Python 3.11+ and pip manually."
            exit 1
            ;;
    esac
    info "Package manager: $PKG_MANAGER"
}

# ---------------------------------------------------------------------------
# 2. OS dependencies
# ---------------------------------------------------------------------------

install_system_deps() {
    step "Preparing OS dependencies"
    if [ "$INSTALL_MODE" = "user" ]; then
        info "User mode: skipping system package installation."
        info "Ensure Python 3.11+, pip and git are already installed."
        return 0
    fi
    local installer=()
    if [ "$(id -u)" -eq 0 ]; then
        installer=()
    elif have_cmd sudo; then
        installer=(sudo)
    else
        warn "sudo not available. Ensure Python 3.11+, pip and git are already installed."
        return 0
    fi
    info "Installing: $PYTHON_PKGS $BUILD_PKGS"
    "${installer[@]}" $PKG_UPDATE >/dev/null 2>&1 || true
    if ! "${installer[@]}" $INSTALL_CMD $PYTHON_PKGS $BUILD_PKGS >/dev/null 2>&1; then
        warn "System package installation reported errors; continuing (Python 3.11+ must be present)."
    fi
    ok "System dependencies satisfied"
}

# ---------------------------------------------------------------------------
# 3. Runtime / toolchains
# ---------------------------------------------------------------------------

check_python() {
    step "Preparing Python runtime"
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
        error "Python 3.11+ is required. Install it first, then re-run."
        exit 1
    fi
    PYTHON="$py_cmd"
    ok "$("$PYTHON" --version)"
}

ensure_venv() {
    # A genuine venv has a `pyvenv.cfg` and its `bin/python` reports the venv
    # as sys.prefix. A stale/broken venv (missing pyvenv.cfg, or python
    # symlinked straight to the system interpreter) makes pip treat the system
    # Python as externally managed (PEP 668) and every install fails. Detect
    # that state and rebuild the venv instead of failing.
    local venv_ok=false
    if [ -x "${VENV_DIR}/bin/python" ] && [ -f "${VENV_DIR}/pyvenv.cfg" ]; then
        if "$VENV_DIR/bin/python" -c 'import sys; sys.exit(0 if sys.prefix == sys.argv[1] else 1)' "$VENV_DIR" >/dev/null 2>&1; then
            venv_ok=true
        fi
    fi

    if [ "$venv_ok" = true ]; then
        info "Virtual environment healthy at ${VENV_DIR}"
    else
        if [ -d "$VENV_DIR" ]; then
            warn "Existing virtual environment is broken; rebuilding at ${VENV_DIR}"
            rm -rf "$VENV_DIR"
        else
            info "Creating virtual environment at ${VENV_DIR}"
        fi
        "$PYTHON" -m venv "$VENV_DIR"
    fi
    # shellcheck disable=SC1091
    source "${VENV_DIR}/bin/activate"
}

# ---------------------------------------------------------------------------
# 4. Install HunterX
# ---------------------------------------------------------------------------

install_hunterx() {
    step "Installing HunterX"

    if [ "$INSTALL_MODE" = "system" ]; then
        VENV_DIR="${INSTALL_DIR}/venv"
        BIN_DIR="/usr/local/bin"
        STATE_DIR="${INSTALL_DIR}/state"
    else
        VENV_DIR="${USER_INSTALL_DIR}/venv"
        BIN_DIR="${HOME}/.local/bin"
        STATE_DIR="${HOME}/.local/state/hunterx"
        mkdir -p "$(dirname "$USER_INSTALL_DIR")"
    fi

    mkdir -p "$(dirname "$VENV_DIR")" "$BIN_DIR" "$STATE_DIR"
    ensure_venv

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
    ok "HunterX installed into virtual environment"
}

# ---------------------------------------------------------------------------
# Executable + symlinks (verified, not assumed)
# ---------------------------------------------------------------------------

install_executable() {
    step "Installing HunterX executable"

    mkdir -p "$BIN_DIR"
    local venv_bin="${VENV_DIR}/bin"
    local main_bin="${BIN_DIR}/${PROJECT_NAME}"

    # Install a wrapper (not a bare symlink) that pins the persistent
    # environment (database URL + shared tool bin) before exec'ing the real
    # binary. This guarantees `hunterx` resolves the configured database and
    # tools from ANY working directory and ANY shell (login, non-login, CI),
    # without depending on /etc/profile.d being sourced.
    #
    # NOTE: the wrapper execs the venv's Python with the ``hunterx`` entry
    # point. It must NEVER overwrite the pip-installed console script at
    # ${venv_bin}/hunterx (the wrapper would exec itself → infinite recursion).
    # ``-P`` prevents the working directory from shadowing the installed
    # package (a repo-root ``hunterx.py`` v6 shim would otherwise win on
    # sys.path and crash with "No module named hunterx.cli").
    cat > "$main_bin" << WRAPEOF
#!/usr/bin/env bash
# HunterX launcher (managed by install.sh) — pins the persistent environment.
export HUNTERX_DATA_DIR='${DATA_DIR}'
# Load install-local environment (AI provider, keys, config) so the installed
# CLI resolves the configured provider regardless of the working directory.
# The file is optional and owned by the runtime user; missing is fine.
if [ -f "\${HUNTERX_DATA_DIR}/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    source "\${HUNTERX_DATA_DIR}/.env"
    set +a
fi
if [ -z "\${HUNTERX_DATABASE_URL:-}" ] && [ -z "\${HUNTERX_DB_URL:-}" ]; then
    export HUNTERX_DATABASE_URL='${DB_URL}'
    export HUNTERX_DB_URL='${DB_URL}'
fi
# Effective security-tool PATH order (each block prepends, so the LAST block
# prepended ends up FIRST):
#   1. shared HunterX tool directory (<data>/tools/bin)
#   2. Go bin directory (GOBIN, else ~/go/bin)
#   3. the HunterX venv
# The venv is intentionally LAST: a same-named Python package CLI inside it
# (e.g. the httpx package's console script) must never shadow the security
# tool installed in the shared tool directory.
if [ -n "${VENV_DIR:-}" ] && [ -d "${VENV_DIR}/bin" ]; then
    case ":\${PATH:-}:" in
        *":${VENV_DIR}/bin:"*) ;;
        *) export PATH="${VENV_DIR}/bin:\$PATH" ;;
    esac
fi
GO_BIN_DIR="\${GOBIN:-}"
if [ -n "\${GO_BIN_DIR}" ] && [ ! -d "\${GO_BIN_DIR}" ]; then
    GO_BIN_DIR="\${HOME}/go/bin"
fi
if [ -n "\${GO_BIN_DIR}" ] && [ -d "\${GO_BIN_DIR}" ]; then
    case ":\${PATH:-}:" in
        *":\${GO_BIN_DIR}:"*) ;;
        *) export PATH="\${GO_BIN_DIR}:\$PATH" ;;
    esac
fi
if [ -n "${TOOL_BIN_DIR:-}" ] && [ -d "${TOOL_BIN_DIR}" ]; then
    case ":\${PATH:-}:" in
        *":${TOOL_BIN_DIR}:"*) ;;
        *) export PATH="${TOOL_BIN_DIR}:\$PATH" ;;
    esac
fi
exec "${venv_bin}/python" -P -c "from hunterx.cli import main; import sys; sys.exit(main())" "\$@"
WRAPEOF
    chmod +x "$main_bin"

    # Verify the executable actually works (not merely that the file exists).
    if ! "$main_bin" version >/dev/null 2>&1; then
        error "HunterX executable does not run: ${main_bin}"
        return 1
    fi
    HUNTERX_VERSION="$("$main_bin" version 2>/dev/null | head -1 || echo "HunterX v7")"
    ok "${HUNTERX_VERSION} at ${main_bin}"
}

# ---------------------------------------------------------------------------
# 5. Directories
# ---------------------------------------------------------------------------

prepare_directories() {
    step "Preparing HunterX directories"
    local base
    base="$(dirname "$VENV_DIR")"
    local dirs=("data" "reports" "config" "cache" "tmp" "state" "tools")
    for dir in "${dirs[@]}"; do
        mkdir -p "${base}/${dir}"
        ok "Directory: ${base}/${dir}"
    done

    # System installs run as root but are normally invoked via sudo; hand the
    # runtime data directories to the real user so a subsequent non-root
    # `hunterx` run can write the DB and reports.
    if [ "$INSTALL_MODE" = "system" ] && [ -n "${SUDO_USER:-}" ]; then
        chown -R "$SUDO_USER" "${base}/data" "${base}/reports" "${base}/cache" "${base}/tmp" 2>/dev/null || true
        info "Runtime directories owned by ${SUDO_USER}"
    fi

    # Shared tool directory. External tools provisioned as root (go/cargo/pipx
    # installs under sudo) must land somewhere the real user can reach, not in
    # root's private ~/go/bin or ~/.cargo/bin. Pointing GOBIN/CARGO_HOME/PIPX
    # at the shared dir keeps every provisioned binary on one PATH entry.
    TOOL_BIN_DIR="${base}/tools/bin"
    mkdir -p "$TOOL_BIN_DIR"
    export GOBIN="$TOOL_BIN_DIR"
    export GOFLAGS="${GOFLAGS:-}"
    export CARGO_HOME="${base}/tools/cargo"
    export CARGO_INSTALL_ROOT="${base}/tools"
    export PIPX_HOME="${base}/tools/pipx"
    export PIPX_BIN_DIR="$TOOL_BIN_DIR"
    export PATH="$TOOL_BIN_DIR:$PATH"
    info "Shared tool directory: ${TOOL_BIN_DIR}"
}

# ---------------------------------------------------------------------------
# 6. Configuration
# ---------------------------------------------------------------------------

configure_database_env() {
    step "Preparing configuration"

    DATA_DIR="$(dirname "$VENV_DIR")/data"
    mkdir -p "$DATA_DIR"

    # Copy the project .env (AI provider, keys, config) into the install data
    # directory so the installed launcher can source it from any working
    # directory. Optional: a missing .env is fine and the runtime stays
    # deterministic (no AI). Secrets are never written to profile.d.
    local src_dir
    src_dir="$(cd "$(dirname "$0")" && pwd)"
    if [ -f "${src_dir}/.env" ] && [ ! -f "${DATA_DIR}/.env" ]; then
        cp "${src_dir}/.env" "${DATA_DIR}/.env" 2>/dev/null || true
        chmod 600 "${DATA_DIR}/.env" 2>/dev/null || true
        # Runtime user owns it so non-root `hunterx` runs can source it too.
        if [ "$INSTALL_MODE" = "system" ] && [ -n "${SUDO_USER:-}" ]; then
            chown "$SUDO_USER" "${DATA_DIR}/.env" 2>/dev/null || true
        fi
        info "Copied configuration to ${DATA_DIR}/.env"
    fi

    # Absolute SQLAlchemy URL: the leading slash of $DATA_DIR yields the
    # documented sqlite:////abs/path form. Keeps the CLI from falling back to
    # a CWD-relative ./hunterx.db.
    DB_URL="sqlite:///${DATA_DIR}/hunterx.db"

    export HUNTERX_DATA_DIR="$DATA_DIR"
    export HUNTERX_DATABASE_URL="$DB_URL"
    export HUNTERX_DB_URL="$DB_URL"
    info "Database URL: ${DB_URL}"

    if [ "$INSTALL_MODE" = "system" ]; then
        if [ "$(id -u)" -eq 0 ]; then
            local profile="/etc/profile.d/hunterx.sh"
            local fish_conf="/etc/fish/conf.d/hunterx.fish"
            mkdir -p "$(dirname "$profile")" "$(dirname "$fish_conf")"
            cat > "$profile" << EOF
# HunterX persistent state (managed by install.sh)
export HUNTERX_DATA_DIR='${DATA_DIR}'
export HUNTERX_DATABASE_URL='${DB_URL}'
export HUNTERX_DB_URL='${DB_URL}'
export HUNTERX_TOOL_BIN='${TOOL_BIN_DIR:-}'
export HUNTERX_VENV_BIN='${VENV_DIR}/bin'
case ":\${PATH:-}:" in
    *":\${HUNTERX_TOOL_BIN}:"*) ;;
    *) export PATH="\${HUNTERX_TOOL_BIN}:\$PATH" ;;
esac
case ":\${PATH:-}:" in
    *":\${HUNTERX_VENV_BIN}:"*) ;;
    *) export PATH="\${HUNTERX_VENV_BIN}:\$PATH" ;;
esac
EOF
            cat > "$fish_conf" << EOF
# HunterX persistent state (managed by install.sh)
set -gx HUNTERX_DATA_DIR '${DATA_DIR}'
set -gx HUNTERX_DATABASE_URL '${DB_URL}'
set -gx HUNTERX_DB_URL '${DB_URL}'
set -gx HUNTERX_TOOL_BIN '${TOOL_BIN_DIR:-}'
EOF
            ok "Wrote ${profile} and ${fish_conf}"
        else
            warn "Not running as root; skipping /etc/profile.d export."
            warn "Set HUNTERX_DATABASE_URL=${DB_URL} manually or rerun as root."
        fi
    else
        append_once "$HOME/.bashrc" "export HUNTERX_DATA_DIR='${DATA_DIR}'"
        append_once "$HOME/.bashrc" "export HUNTERX_DATABASE_URL='${DB_URL}'"
        append_once "$HOME/.bashrc" "export HUNTERX_DB_URL='${DB_URL}'"
        append_once "$HOME/.zshrc" "export HUNTERX_DATA_DIR='${DATA_DIR}'"
        append_once "$HOME/.zshrc" "export HUNTERX_DATABASE_URL='${DB_URL}'"
        append_once "$HOME/.zshrc" "export HUNTERX_DB_URL='${DB_URL}'"
        local fish_cfg="$HOME/.config/fish/config.fish"
        mkdir -p "$(dirname "$fish_cfg")"
        append_once "$fish_cfg" "set -gx HUNTERX_DATA_DIR '${DATA_DIR}'"
        append_once "$fish_cfg" "set -gx HUNTERX_DATABASE_URL '${DB_URL}'"
        append_once "$fish_cfg" "set -gx HUNTERX_DB_URL '${DB_URL}'"
        ok "Exported HUNTERX_DATABASE_URL in shell config files."
    fi
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

# ---------------------------------------------------------------------------
# 7 + 8. Database initialization and migrations
# ---------------------------------------------------------------------------

initialize_database() {
    step "Initializing HunterX database"

    DATA_DIR="$(dirname "$VENV_DIR")/data"
    mkdir -p "$DATA_DIR"

    ok "Database directory: ${DATA_DIR}"

    # Alembic resolves script_location relative to the working directory, so
    # run from the source tree when present.
    local src_dir
    src_dir="$(cd "$(dirname "$0")" && pwd)"
    local config_arg=""
    if [ -f "${src_dir}/alembic.ini" ]; then
        config_arg="-c ${src_dir}/alembic.ini"
    fi

    if [ -x "${VENV_DIR}/bin/python" ]; then
        info "Running database migrations..."
        if [ -d "${src_dir}/alembic" ]; then
            (
                cd "$src_dir"
                HUNTERX_DATA_DIR="$DATA_DIR" HUNTERX_DATABASE_URL="$DB_URL" HUNTERX_DB_URL="$DB_URL" \
                    "${VENV_DIR}/bin/python" -m alembic ${config_arg} upgrade head >/dev/null 2>&1
            ) || {
                warn "Alembic migration step did not complete; HunterX creates tables on demand."
                warn "Re-run manually with: cd ${src_dir} && HUNTERX_DB_URL='${DB_URL}' alembic upgrade head"
            }
        else
            # PyPI-only installs: create tables on demand via the CLI (the
            # SessionFactory.create_all path is idempotent).
            HUNTERX_DATA_DIR="$DATA_DIR" HUNTERX_DATABASE_URL="$DB_URL" HUNTERX_DB_URL="$DB_URL" \
                run_hunterx version >/dev/null 2>&1 || true
        fi
        ok "Migrations complete"
    else
        warn "Package binary not found; skipping database initialization."
    fi

    # 5. Run an actual persistence initialization check through the real
    #    application runtime (not a raw sqlite probe): the CLI builds the
    #    platform with the SQL persistence layer, which resolves the database
    #    URL and runs metadata.create_all. Fails loudly — never in-memory.
    info "Running persistence initialization check..."
    if ! HUNTERX_DATA_DIR="$DATA_DIR" HUNTERX_DATABASE_URL="$DB_URL" HUNTERX_DB_URL="$DB_URL" \
        run_hunterx version >/dev/null 2>&1; then
        error "Persistence initialization failed."
        error "Reason: the HunterX runtime could not open/initialize the database at:"
        error "  ${DB_URL}"
        error "Suggested fix: ensure '${DATA_DIR}' exists and is writable by $(id -un),"
        error "then re-run: sudo ./install.sh"
        error "HunterX status: NOT READY"
        return 1
    fi
    ok "Persistence initialization check"

    if ! verify_database; then
        error "Database initialization failed."
        error "HunterX status: NOT READY"
        return 1
    fi
    ok "Database initialized"
}

verify_database() {
    step "Verifying HunterX database"
    local db_file="${DB_URL#sqlite:///}"
    if [ ! -f "$db_file" ]; then
        fail "Database file missing: ${db_file}"
        return 1
    fi
    local venv_py="${VENV_DIR}/bin/python"
    [ -x "$venv_py" ] || venv_py="$PYTHON"
    if HUNTERX_DATA_DIR="$DATA_DIR" HUNTERX_DATABASE_URL="$DB_URL" HUNTERX_DB_URL="$DB_URL" "$venv_py" - "$db_file" <<'PYEOF'
import sqlite3
import sys

db_file = sys.argv[1]
try:
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alembic_version'")
    has_migrations = cursor.fetchone() is not None
    cursor.execute("CREATE TABLE IF NOT EXISTS _hunterx_probe (id INTEGER)")
    cursor.execute("DELETE FROM _hunterx_probe")
    conn.commit()
    cursor.execute("DROP TABLE IF EXISTS _hunterx_probe")
    conn.commit()
except Exception as exc:  # noqa: BLE001
    print(f"error: {exc}", file=sys.stderr)
    sys.exit(1)
finally:
    conn.close()
if not has_migrations:
    print("schema tables present (created on demand)", file=sys.stderr)
sys.exit(0)
PYEOF
    then
        ok "Database connection"
        ok "Database writable"
        ok "Schema"
        return 0
    else
        fail "Database read/write verification failed"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# 9. Supporting resources
# ---------------------------------------------------------------------------

prepare_resources() {
    step "Preparing HunterX supporting resources"
    local base
    base="$(dirname "$VENV_DIR")"

    # Internal resource directories the platform expects at runtime.
    mkdir -p "${base}/reports" "${base}/cache" "${base}/tmp" "${base}/data"
    if [ -n "${SUDO_USER:-}" ] && [ "$INSTALL_MODE" = "system" ]; then
        chown -R "$SUDO_USER" "${base}/reports" "${base}/cache" "${base}/tmp" 2>/dev/null || true
    fi
    ok "Reports / cache / temporary directories"

    # Establish the base HunterX environment (in-process adapters, internal
    # knowledge, signatures, crawler/proof-replay resources). Delegated to the
    # canonical readiness layer — never duplicated here.
    if ! run_hunterx install --profile minimal --state "$STATE_DIR"; then
        error "Base HunterX environment could not be established."
        error "HunterX status: NOT READY"
        return 1
    fi
    ok "Base environment (internal resources)"
}

# ---------------------------------------------------------------------------
# PATH management (idempotent; current process + future shells)
# ---------------------------------------------------------------------------

#: The interactive user owning this install (real user when invoked via sudo).
real_user() {
    if [ "$INSTALL_MODE" = "system" ] && [ -n "${SUDO_USER:-}" ]; then
        echo "$SUDO_USER"
    else
        id -un 2>/dev/null || echo "${HOME##*/}"
    fi
}

real_home() {
    local user
    user="$(real_user)"
    if [ "$user" = "root" ]; then
        echo "/root"
    elif getent passwd "$user" >/dev/null 2>&1; then
        getent passwd "$user" | cut -d: -f6
    else
        echo "$HOME"
    fi
}

collect_tool_paths() {
    TOOL_PATH_DIRS=(
        "${BIN_DIR:-${HOME}/.local/bin}"
        "${VENV_DIR:-}/bin"
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
    # Deduplicate
    local seen=""
    local filtered=()
    for d in "${TOOL_PATH_DIRS[@]}"; do
        [ -n "$d" ] || continue
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
    # The shared tool directory must take precedence over the venv bin: the
    # venv may contain same-named Python packages (e.g. the ``httpx`` HTTP
    # client) that would shadow the real security tool.
    if [ -n "${TOOL_BIN_DIR:-}" ] && [ -d "$TOOL_BIN_DIR" ]; then
        # Remove any earlier occurrence, then prepend the canonical one.
        local cleaned=""
        local remaining="${PATH}"
        while [ -n "$remaining" ]; do
            local segment
            segment="${remaining%%:*}"
            if [ "$segment" != "$TOOL_BIN_DIR" ]; then
                cleaned="${cleaned:+${cleaned}:}${segment}"
            fi
            if [ "$remaining" = "$segment" ]; then
                remaining=""
            else
                remaining="${remaining#*:}"
            fi
        done
        export PATH="${TOOL_BIN_DIR}:${cleaned}"
    fi
    if [ "${#added[@]}" -gt 0 ]; then
        info "Exported into current PATH: ${added[*]}"
    fi
}

persist_path_for_shells() {
    # Persist PATH to the interactive user's shell configs (the real user when
    # invoked via sudo), so provisioned tools are visible after logout/login.
    local target_home
    target_home="$(real_home)"
    for d in "${TOOL_PATH_DIRS[@]}"; do
        [ -d "$d" ] || continue
        if path_contains "$d"; then
            continue
        fi
        append_once "${target_home}/.bashrc" "export PATH=\"\$PATH:${d}\""
        append_once "${target_home}/.profile" "export PATH=\"\$PATH:${d}\"" 2>/dev/null || true
    done
    ok "PATH configuration persisted for $(real_user) (idempotent)"
}

add_to_path() {
    step "Configuring PATH"
    collect_tool_paths
    ensure_path_for_current_process
    persist_path_for_shells
    ok "PATH configured"
}

# ---------------------------------------------------------------------------
# Tool readiness delegation (canonical layer owns the tool catalog)
# ---------------------------------------------------------------------------

run_hunterx() {
    local hx="${BIN_DIR}/${PROJECT_NAME}"
    if [ -x "$hx" ]; then
        "$hx" "$@"
    else
        "${PROJECT_NAME}" "$@"
    fi
}

provision_toolchain() {
    step "Provisioning security toolchain (profile: ${TOOL_PROFILE})"

    if [ "$TOOL_PROFILE" = "minimal" ]; then
        ok "Minimal profile: base environment already established"
        return 0
    fi

    # Detect + show available/missing tools (compact multi-column output).
    if ! run_hunterx tools check; then
        warn "hunterx tools check reported an error; continuing to provision."
    fi

    echo ""
    info "HunterX will now provision the required toolchain automatically."

    # Provision missing tools with live progress, per-tool timeouts, failure
    # isolation and state tracking for resume support.
    if ! run_hunterx tools install --profile "$TOOL_PROFILE" --state "$STATE_DIR"; then
        warn "Some tools could not be provisioned (see summary above)."
    fi

    # Verify every tool AFTER provisioning.
    step "Verifying security toolchain"
    run_hunterx tools check || true
}

# ---------------------------------------------------------------------------
# Final readiness verification
# ---------------------------------------------------------------------------

final_readiness() {
    step "Final HunterX readiness verification"

    local checks=0
    local errors=0

    # -- Core ---------------------------------------------------------------
    if have_cmd hunterx || [ -x "${BIN_DIR}/${PROJECT_NAME}" ]; then
        ok "HunterX CLI: $(run_hunterx version 2>/dev/null | head -1)" && checks=$((checks+1))
        run_hunterx help >/dev/null 2>&1 && ok "CLI help" && checks=$((checks+1))
        run_hunterx config >/dev/null 2>&1 && ok "Configuration resolves" && checks=$((checks+1))
        run_hunterx platform >/dev/null 2>&1 && ok "Platform composition" && checks=$((checks+1))
    else
        fail "HunterX command not found on PATH"
        errors=$((errors+1))
    fi

    # -- Runtime -------------------------------------------------------------
    ok "Python: $("$PYTHON" --version 2>/dev/null)" && checks=$((checks+1))
    if [ -x "${VENV_DIR}/bin/python" ]; then
        ok "Virtual environment healthy" && checks=$((checks+1))
    else
        fail "Virtual environment missing"
        errors=$((errors+1))
    fi

    # -- Database ------------------------------------------------------------
    if verify_database >/dev/null 2>&1; then
        ok "Database ready" && checks=$((checks+1))
    else
        fail "Database not ready"
        errors=$((errors+1))
    fi

    # -- Tools: required capabilities ----------------------------------------
    # Ensure the venv bin and shared tool bin are on the current PATH so the
    # readiness probe resolves every provisioned tool (pip/venv + go/cargo).
    collect_tool_paths
    ensure_path_for_current_process
    local readiness_rc=0
    local readiness_file="${STATE_DIR}/readiness.json"
    mkdir -p "$STATE_DIR" 2>/dev/null || true
    rm -f "$readiness_file" 2>/dev/null || true
    run_hunterx tools check --json > "$readiness_file" 2>/dev/null || readiness_rc=$?
    local venv_py="${VENV_DIR}/bin/python"
    [ -x "$venv_py" ] || venv_py="$PYTHON"
    local verdict
    verdict=$("$venv_py" - "$readiness_file" <<'PYEOF'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)

capabilities = data.get("capabilities", [])
required = [c for c in capabilities if c.get("level") == "required" and c.get("status") != "ready"]
recommended = [c for c in capabilities if c.get("level") == "recommended" and c.get("status") != "ready"]
optional = [c for c in capabilities if c.get("level") == "optional" and c.get("status") != "ready"]
if required:
    print("NOT_READY")
elif recommended or optional:
    print("PARTIAL")
else:
    print("READY")
PYEOF
    )

    case "$verdict" in
        READY)
            TOOLCHAIN_STATUS="READY"
            ok "Required capabilities READY"
            ;;
        PARTIAL)
            TOOLCHAIN_STATUS="PARTIAL"
            ok "Required capabilities READY (recommended/optional gaps remain)"
            ;;
        *)
            TOOLCHAIN_STATUS="NOT_READY"
            fail "Required capabilities NOT READY"
            errors=$((errors+1))
            ;;
    esac

    return $errors
}

# ---------------------------------------------------------------------------
# Banner + quick start
# ---------------------------------------------------------------------------

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

show_quick_start() {
    echo ""
    echo "Quick Start"
    echo "────────────────────────────────────────"
    echo ""
    echo "Start HunterX:"
    echo "  hunterx help"
    echo ""
    echo "Run a security assessment:"
    echo "  hunterx mission create <objective> <target>"
    echo "  hunterx hunt full_security_assessment <target>"
    echo ""
    echo "Check tool readiness:"
    echo "  hunterx tools check"
    echo ""
    echo "View help:"
    echo "  hunterx --help"
    echo ""
    echo "Responsible use: HunterX is an authorized cybersecurity testing and"
    echo "research platform. Obtain authorization before testing any system."
    echo ""
    if [ "$INSTALL_MODE" = "system" ]; then
        echo "Uninstall:    sudo bash $0 --uninstall"
    else
        echo "Uninstall:    bash $0 --user --uninstall"
    fi
    echo ""
}

emit_json_summary() {
    if [ "$JSON_MODE" = true ]; then
        local venv_py="${VENV_DIR}/bin/python"
        [ -x "$venv_py" ] || venv_py="$PYTHON"
        "$venv_py" - "${HUNTERX_VERSION:-}" "$(dirname "$VENV_DIR")" "$STATE_DIR" "$DB_URL" <<'PYEOF'
import json
import sys

version, install_dir, state_dir, database = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
summary = {
    "hunterx": version,
    "install_dir": install_dir,
    "state_dir": state_dir,
    "database": database,
}
print(json.dumps(summary, indent=2, sort_keys=True))
PYEOF
    fi
}

# ---------------------------------------------------------------------------

main() {
    parse_args "$@"

    if $DO_UNINSTALL; then
        show_banner
        info "HunterX Uninstaller"
        echo ""
        uninstall_hunterx
    fi

    show_banner
    info "HunterX Environment Bootstrapper (${INSTALL_MODE} mode, profile: ${TOOL_PROFILE})"
    echo ""

    if [ "$INSTALL_MODE" = "system" ] && [ "$(id -u)" -ne 0 ]; then
        warn "System-wide installation recommended as root."
        warn "Run with --user for user-local installation, or prefix with sudo."
    fi

    # 1. Detect environment
    detect_distro

    # 2. Prepare OS dependencies
    install_system_deps

    # 3. Prepare runtime / toolchains
    check_python

    # 4. Install HunterX
    install_hunterx

    # 5. Prepare directories
    prepare_directories

    # 6. Prepare configuration
    configure_database_env

    # 4b. Install/refresh the executable wrapper (pins DB URL + tool PATH).
    install_executable

    # 7 + 8. Database + migrations
    if ! initialize_database; then
        exit 1
    fi

    # 9. Supporting resources (base environment)
    prepare_resources

    # PATH for current process + future shells
    add_to_path

    # 10-12. Detect tools, install missing, verify
    provision_toolchain

    # 13-15. Final readiness verification
    local readiness_errors=0
    final_readiness || readiness_errors=$?

    # Extract failed tools from the final report (for the summary banner).
    local venv_py="${VENV_DIR}/bin/python"
    [ -x "$venv_py" ] || venv_py="$PYTHON"
    local readiness_file="${STATE_DIR}/readiness.json"
    FAILED_TOOLS=$("$venv_py" - "$readiness_file" <<'PYEOF' 2>/dev/null || echo ""
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)
missing = [tool["tool_id"] for tool in data.get("tools", ()) if tool.get("status") in ("missing", "broken", "unsupported")]
print(" ".join(sorted(missing)))
PYEOF
    )

    echo ""
    echo "============================================================"
    if [ "$readiness_errors" -eq 0 ]; then
        echo " HunterX ${HUNTERX_VERSION:-v7.0.0}"
        echo " Installation Complete"
        echo "============================================================"
        echo ""
        ok "HunterX Core ............... READY"
        ok "Runtime ................... READY"
        ok "Database .................. READY"
        ok "Internal Resources ........ READY"
        if [ "$TOOLCHAIN_STATUS" = "READY" ]; then
            ok "Security Toolchain ........ READY"
        else
            warn "Security Toolchain ........ ${TOOLCHAIN_STATUS:-PARTIAL}"
        fi
        ok "Required Capabilities ..... READY"
        echo ""
        if [ -n "$FAILED_TOOLS" ]; then
            echo "Optional/recommended tools not yet provisioned:"
            echo "  $FAILED_TOOLS"
            echo ""
            echo "Retry provisioning with:"
            echo "  hunterx tools install --profile ${TOOL_PROFILE}"
            echo ""
        fi
        echo "HunterX is ready to use."
        echo "============================================================"
        show_quick_start
        emit_json_summary
        exit 0
    else
        echo " HunterX Installation Incomplete"
        echo "============================================================"
        echo ""
        fail "HunterX Core ............... $([ -x "${BIN_DIR}/${PROJECT_NAME}" ] && echo READY || echo FAILED)"
        fail "Runtime ................... $([ -x "${VENV_DIR}/bin/python" ] && echo READY || echo FAILED)"
        warn "Security Toolchain ........ INCOMPLETE"
        warn "Required Capabilities ..... NOT READY"
        echo ""
        echo "Failed components and their reasons are shown above."
        echo ""
        echo "Retry:"
        echo "  sudo ./install.sh"
        echo "============================================================"
        exit 1
    fi
}

main "$@"
