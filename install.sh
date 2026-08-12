#!/usr/bin/env bash
# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX v7 — AI-Powered Security Orchestration & Intelligence Platform
# Production Linux Installer
#
# Supports: Ubuntu, Debian, Fedora, RHEL, Arch, Alpine, openSUSE
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/nullc0d30/HunterX/main/install.sh | sudo bash
#   curl -sSL https://raw.githubusercontent.com/nullc0d30/HunterX/main/install.sh | bash -s -- --user
#   curl -sSL https://raw.githubusercontent.com/nullc0d30/HunterX/main/install.sh | sudo bash -s -- --all
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
REQUIRED_DIRS=("data" "reports" "config")

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
                shift
                ;;
            --all)
                EXTRAS="all"
                shift
                ;;
            --help|-h)
                echo "Usage: install.sh [--user] [--core|--all] [--uninstall]"
                echo ""
                echo "  --user       Install to user home directory (no root/sudo required)"
                echo "  --core       Install only the core package (no REST API / database extras)"
                echo "  --all        Install every optional extra (api, db, report, ai, ...)"
                echo "  --uninstall  Remove HunterX installation"
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

    # Clean PATH exports from shell configs
    local cleaned=false
    for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
        if [ -f "$rc" ]; then
            sed -i "\|export PATH=\$PATH:${bins[0]%/*}|d" "$rc" 2>/dev/null || true
            cleaned=true
        fi
    done
    if [ -f "$HOME/.config/fish/config.fish" ]; then
        sed -i "\|set -gx PATH \$PATH ${bins[0]%/*}|d" "$HOME/.config/fish/config.fish" 2>/dev/null || true
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

add_to_path() {
    step "Verifying PATH"
    local need_warn=false

    if ! echo "$PATH" | tr ':' '\n' | grep -qx "$BIN_DIR" >/dev/null 2>&1; then
        warn "${BIN_DIR} is not in PATH."
        if [ -f "$HOME/.bashrc" ] && [ "$BIN_DIR" != "/usr/local/bin" ]; then
            if ! grep -q "export PATH=\$PATH:${BIN_DIR}" "$HOME/.bashrc" 2>/dev/null; then
                echo "export PATH=\$PATH:${BIN_DIR}" >> "$HOME/.bashrc"
                info "Added to ~/.bashrc. Run: source ~/.bashrc"
            fi
        fi
        if [ -f "$HOME/.zshrc" ] && [ "$BIN_DIR" != "/usr/local/bin" ]; then
            if ! grep -q "export PATH=\$PATH:${BIN_DIR}" "$HOME/.zshrc" 2>/dev/null; then
                echo "export PATH=\$PATH:${BIN_DIR}" >> "$HOME/.zshrc"
                info "Added to ~/.zshrc. Run: source ~/.zshrc"
            fi
        fi
        if [ -f "$HOME/.config/fish/config.fish" ] && [ "$BIN_DIR" != "/usr/local/bin" ]; then
            if ! grep -q "set -gx PATH \$PATH ${BIN_DIR}" "$HOME/.config/fish/config.fish" 2>/dev/null; then
                echo "set -gx PATH \$PATH ${BIN_DIR}" >> "$HOME/.config/fish/config.fish"
                info "Added to fish config. Run: source ~/.config/fish/config.fish"
            fi
        fi
        need_warn=true
    fi

    export PATH="${BIN_DIR}:${PATH}"

    if $need_warn; then
        warn "Log out and back in, or run: export PATH=\$PATH:${BIN_DIR}"
    else
        info "PATH OK"
    fi
}

verify_installation() {
    step "Verifying installation"
    local errors=0

    echo ""
    if have_cmd hunterx; then
        info "1/5: hunterx version"
        hunterx version || { error "FAILED"; errors=$((errors+1)); }
        info "2/5: hunterx help"
        hunterx help >/dev/null 2>&1 && echo "  (help rendered OK)" || { error "FAILED"; errors=$((errors+1)); }
        info "3/5: hunterx config"
        hunterx config >/dev/null 2>&1 && echo "  (config resolved OK)" || { error "FAILED"; errors=$((errors+1)); }
        info "4/5: hunterx platform"
        hunterx platform >/dev/null 2>&1 && echo "  (platform composition OK)" || { error "FAILED"; errors=$((errors+1)); }
        info "5/5: hunterx tools list"
        hunterx tools list >/dev/null 2>&1 && echo "  (toolchain catalog OK)" || {
            warn "Toolchain catalog did not render. This is not fatal."
        }
    else
        error "1/5: hunterx command not found on PATH"
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
    info "HunterX Linux Installer (${INSTALL_MODE} mode)"
    echo ""

    if [ "$INSTALL_MODE" = "system" ] && [ "$(id -u)" -ne 0 ]; then
        warn "System-wide installation recommended as root."
        warn "Run with --user for user-local installation, or prefix with sudo."
    fi

    detect_distro
    install_system_deps
    check_python
    install_hunterx
    install_executable
    initialize_database
    add_to_path
    verify_installation

    echo ""
    info "Installation complete!"
    echo ""
    echo "  Quick start:  hunterx help"
    echo "  Mission:      hunterx mission create <objective> <target>"
    echo "  Hunt:         hunterx hunt <objective> <target>"
    echo "  Toolchain:    hunterx tools list"
    echo "  Config:       hunterx config"
    echo "  Version:      hunterx version"
    echo "  Platform:     hunterx platform"
    echo ""
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
