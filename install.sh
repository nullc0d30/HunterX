#!/usr/bin/env bash
# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
# Production Linux Installer
#
# Supports: Ubuntu, Debian, Fedora, RHEL, Arch, Alpine, openSUSE
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/nullc0d30/HunterX/main/install.sh | sudo bash
#   curl -sSL https://raw.githubusercontent.com/nullc0d30/HunterX/main/install.sh | bash -s -- --user
#   curl -sSL https://raw.githubusercontent.com/nullc0d30/HunterX/main/install.sh | sudo bash -s -- --uninstall
#   curl -sSL https://raw.githubusercontent.com/nullc0d30/HunterX/main/install.sh | bash -s -- --user --uninstall

set -euo pipefail

INSTALL_DIR="/opt/hunterx"
USER_INSTALL_DIR="${HOME}/.local/share/hunterx"
VENV_DIR=""
BIN_DIR=""
PROJECT_NAME="hunterx"
SYMLINKS=("HunterX" "Hunterx" "hunterX" "HUNTERX")
INSTALL_MODE="system"
DO_UNINSTALL=false

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
            --help|-h)
                echo "Usage: install.sh [--user] [--uninstall]"
                echo ""
                echo "  --user       Install to user home directory (no root/sudo required)"
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

verify_checksum() {
    local file="$1"
    local expected_hash="$2"
    if [ -z "$expected_hash" ]; then
        return 0
    fi
    if have_cmd sha256sum; then
        local actual_hash
        actual_hash=$(sha256sum "$file" | cut -d' ' -f1)
        if [ "$actual_hash" != "$expected_hash" ]; then
            error "Checksum mismatch for $file"
            error "Expected: $expected_hash"
            error "Actual:   $actual_hash"
            return 1
        fi
        info "Checksum verified for $file"
    elif have_cmd shasum; then
        local actual_hash
        actual_hash=$(shasum -a 256 "$file" | cut -d' ' -f1)
        if [ "$actual_hash" != "$expected_hash" ]; then
            error "Checksum mismatch for $file"
            return 1
        fi
        info "Checksum verified for $file"
    else
        warn "No checksum tool available, skipping verification."
    fi
    return 0
}

install_hunterx() {
    step "Installing HunterX"

    if [ "$INSTALL_MODE" = "system" ]; then
        VENV_DIR="${INSTALL_DIR}/venv"
        BIN_DIR="/usr/local/bin"
        if [ -d "$INSTALL_DIR" ]; then
            warn "Previous installation found at ${INSTALL_DIR}. Reinstalling..."
            rm -rf "$INSTALL_DIR"
        fi
    else
        VENV_DIR="${USER_INSTALL_DIR}/venv"
        BIN_DIR="${HOME}/.local/bin"
        mkdir -p "$(dirname "$USER_INSTALL_DIR")"
        if [ -d "$USER_INSTALL_DIR" ]; then
            warn "Previous installation found at ${USER_INSTALL_DIR}. Reinstalling..."
            rm -rf "$USER_INSTALL_DIR"
        fi
        mkdir -p "$BIN_DIR"
    fi

    info "Creating virtual environment at ${VENV_DIR}"
    mkdir -p "$(dirname "$VENV_DIR")"
    "$PYTHON" -m venv "$VENV_DIR"
    # shellcheck disable=SC1091
    source "${VENV_DIR}/bin/activate"

    pip install --upgrade pip >/dev/null 2>&1 || true

    local src_dir
    src_dir="$(cd "$(dirname "$0")" && pwd)"
    if [ -f "${src_dir}/pyproject.toml" ]; then
        info "Installing from local source: ${src_dir}"
        pip install --no-cache-dir "$src_dir" >/dev/null 2>&1 || {
            error "pip install from local source failed."
            exit 1
        }
    else
        info "Local source not found. Installing from PyPI..."
        local pkg_hash=""
        if [ -n "${HUNTERX_PACKAGE_HASH:-}" ] && have_cmd curl; then
            # Try to verify the package checksum before installing
            local tmp_dir
            tmp_dir=$(mktemp -d)
            curl -sSL "https://files.pythonhosted.org/packages/source/h/hunterx/hunterx-6.0.0.tar.gz" -o "${tmp_dir}/hunterx.tar.gz" 2>/dev/null || true
            if [ -f "${tmp_dir}/hunterx.tar.gz" ]; then
                if verify_checksum "${tmp_dir}/hunterx.tar.gz" "$pkg_hash"; then
                    pip install --no-cache-dir "${tmp_dir}/hunterx.tar.gz" >/dev/null 2>&1 || {
                        warn "Verified package install failed, falling back to PyPI..."
                        pip install --no-cache-dir "$PROJECT_NAME" >/dev/null 2>&1 || {
                            error "pip install from PyPI failed."
                            rm -rf "$tmp_dir"
                            exit 1
                        }
                    }
                else
                    warn "Checksum verification failed, falling back to PyPI..."
                    pip install --no-cache-dir "$PROJECT_NAME" >/dev/null 2>&1 || {
                        error "pip install from PyPI failed."
                        rm -rf "$tmp_dir"
                        exit 1
                    }
                fi
                rm -rf "$tmp_dir"
            else
                pip install --no-cache-dir "$PROJECT_NAME" >/dev/null 2>&1 || {
                    error "pip install from PyPI failed."
                    exit 1
                }
            fi
        else
            pip install --no-cache-dir "$PROJECT_NAME" >/dev/null 2>&1 || {
                error "pip install from PyPI failed."
                exit 1
            }
        fi
    fi

    deactivate
    info "HunterX installed into virtual environment"
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
        info "1/3: hunterx --help"
        hunterx --help && echo "" || { error "FAILED"; errors=$((errors+1)); }
    else
        error "1/3: hunterx command not found on PATH"
        errors=$((errors+1))
    fi

    if have_cmd hunterx; then
        info "2/3: hunterx --version"
        hunterx --version || { error "FAILED"; errors=$((errors+1)); }
    fi

    if have_cmd hunterx; then
        info "3/3: hunterx example.com --dry-run (quick smoke test)"
        hunterx example.com --dry-run --preset quick 2>&1 | head -20 && echo "" || {
            warn "Smoke test did not complete (may need network). This is not fatal."
        }
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
    echo " HunterX v6.0 -- AI-Assisted Vulnerability Hunter"
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
    add_to_path
    verify_installation

    echo ""
    info "Installation complete!"
    echo ""
    echo "  Quick start:  hunterx example.com"
    echo "  Help:         hunterx --help"
    echo "  Config:       hunterx config --show"
    echo "  Doctor:       hunterx doctor"
    echo "  Update:       hunterx update"
    echo ""
    if [ "$INSTALL_MODE" = "system" ]; then
        echo "  Uninstall:    sudo bash $0 --uninstall"
    else
        echo "  Uninstall:    bash $0 --user --uninstall"
    fi
    echo ""
}

main "$@"
