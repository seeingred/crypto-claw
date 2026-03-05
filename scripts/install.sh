#!/usr/bin/env bash
set -euo pipefail

# Crypto Claw Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/seeingred/crypto-claw/main/scripts/install.sh | bash
#
# Environment variables:
#   CRYPTO_CLAW_DIR   - Installation directory (default: $HOME/.crypto-claw)
#   CRYPTO_CLAW_REPO  - Git repository URL (default: https://github.com/seeingred/crypto-claw.git)
#   SKIP_BROWSER      - Set to 1 to skip auto-opening the browser

# ---------------------------------------------------------------------------
# Colors and formatting
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

info()    { printf "${CYAN}[INFO]${NC}  %s\n" "$*"; }
success() { printf "${GREEN}[OK]${NC}    %s\n" "$*"; }
warn()    { printf "${YELLOW}[WARN]${NC}  %s\n" "$*"; }
error()   { printf "${RED}[ERROR]${NC} %s\n" "$*" >&2; }
fatal()   { error "$@"; exit 1; }

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
printf "${BOLD}${CYAN}"
cat << 'BANNER'

   ____                  _           ____ _
  / ___|_ __ _   _ _ __ | |_ ___    / ___| | __ ___      __
 | |   | '__| | | | '_ \| __/ _ \  | |   | |/ _` \ \ /\ / /
 | |___| |  | |_| | |_) | || (_) | | |___| | (_| |\ V  V /
  \____|_|   \__, | .__/ \__\___/   \____|_|\__,_| \_/\_/
             |___/|_|
  MPC-TSS Crypto Signing Service

BANNER
printf "${NC}"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
REPO_URL="${CRYPTO_CLAW_REPO:-https://github.com/seeingred/crypto-claw.git}"
INSTALL_DIR="${CRYPTO_CLAW_DIR:-$HOME/.crypto-claw}"
MIN_GO_MAJOR=1
MIN_GO_MINOR=21
INSTALLER_PORT=3000

# ---------------------------------------------------------------------------
# OS / Architecture detection
# ---------------------------------------------------------------------------
detect_platform() {
    OS="$(uname -s)"
    ARCH="$(uname -m)"

    case "$OS" in
        Linux*)
            PLATFORM="linux"
            # Detect WSL
            if grep -qiE '(microsoft|wsl)' /proc/version 2>/dev/null; then
                PLATFORM_LABEL="Linux (WSL)"
            else
                PLATFORM_LABEL="Linux"
            fi
            ;;
        Darwin*)
            PLATFORM="darwin"
            PLATFORM_LABEL="macOS"
            ;;
        *)
            fatal "Unsupported operating system: $OS. This installer supports macOS, Linux, and WSL."
            ;;
    esac

    case "$ARCH" in
        x86_64)          GOARCH="amd64" ;;
        aarch64|arm64)   GOARCH="arm64" ;;
        *)               fatal "Unsupported architecture: $ARCH" ;;
    esac

    success "Detected platform: ${PLATFORM_LABEL} (${PLATFORM}/${GOARCH})"
}

# ---------------------------------------------------------------------------
# Prerequisite checks
# ---------------------------------------------------------------------------
check_go() {
    if ! command -v go &>/dev/null; then
        fatal "Go is required but not installed. Install Go ${MIN_GO_MAJOR}.${MIN_GO_MINOR}+ from https://go.dev/dl/"
    fi

    local go_version
    go_version="$(go version | grep -oE 'go[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)"
    local major minor
    major="$(echo "$go_version" | grep -oE '[0-9]+' | sed -n '1p')"
    minor="$(echo "$go_version" | grep -oE '[0-9]+' | sed -n '2p')"

    if [ -z "$major" ] || [ -z "$minor" ]; then
        warn "Could not parse Go version from '$(go version)'. Proceeding anyway."
        return
    fi

    if [ "$major" -lt "$MIN_GO_MAJOR" ] || { [ "$major" -eq "$MIN_GO_MAJOR" ] && [ "$minor" -lt "$MIN_GO_MINOR" ]; }; then
        fatal "Go ${MIN_GO_MAJOR}.${MIN_GO_MINOR}+ is required, but found go${major}.${minor}. Upgrade from https://go.dev/dl/"
    fi

    success "Go found: $(go version)"
}

check_git() {
    if ! command -v git &>/dev/null; then
        fatal "git is required but not installed. Install git from https://git-scm.com/"
    fi
    success "git found: $(git --version)"
}

check_node() {
    if ! command -v node &>/dev/null; then
        warn "Node.js not found. It is required to build the installer UI."
        warn "Install Node.js 18+ from https://nodejs.org/"
        return 1
    fi
    success "Node.js found: $(node --version)"
    return 0
}

check_npm() {
    if ! command -v npm &>/dev/null; then
        warn "npm not found. It is required to build the installer UI."
        return 1
    fi
    success "npm found: $(npm --version)"
    return 0
}

check_docker() {
    if command -v docker &>/dev/null; then
        success "Docker found: $(docker --version)"
    else
        warn "Docker not found. You will need it for deployment."
        warn "Install Docker from https://docs.docker.com/get-docker/"
    fi
}

# ---------------------------------------------------------------------------
# Clone or update repository
# ---------------------------------------------------------------------------
setup_source() {
    local src_dir="$INSTALL_DIR/src"

    if [ -d "$src_dir/.git" ]; then
        info "Existing source found at $src_dir. Updating..."
        if ! git -C "$src_dir" pull --ff-only 2>/dev/null; then
            warn "Could not fast-forward. Using existing source as-is."
        fi
        success "Source updated."
    else
        info "Cloning repository..."
        mkdir -p "$INSTALL_DIR"
        git clone "$REPO_URL" "$src_dir"
        success "Repository cloned to $src_dir"
    fi
}

# ---------------------------------------------------------------------------
# Build the installer binary
# ---------------------------------------------------------------------------
build_installer() {
    local src_dir="$INSTALL_DIR/src"
    local bin_dir="$INSTALL_DIR/bin"

    mkdir -p "$bin_dir"

    info "Building installer binary..."
    (
        cd "$src_dir"
        CGO_ENABLED=0 GOOS="$PLATFORM" GOARCH="$GOARCH" \
            go build -ldflags="-s -w" -o "$bin_dir/crypto-claw-installer" ./cmd/installer
    )
    success "Installer binary built: $bin_dir/crypto-claw-installer"
}

# ---------------------------------------------------------------------------
# Build the Svelte frontend
# ---------------------------------------------------------------------------
build_frontend() {
    local ui_dir="$INSTALL_DIR/src/installer/ui"

    if [ ! -d "$ui_dir" ]; then
        warn "Installer UI directory not found at $ui_dir. Skipping frontend build."
        return 0
    fi

    info "Installing frontend dependencies..."
    (cd "$ui_dir" && npm install --no-fund --no-audit 2>&1) || {
        error "Failed to install frontend dependencies."
        warn "The installer will run without the web UI. Check Node.js and npm."
        return 0
    }
    success "Frontend dependencies installed."

    info "Building frontend..."
    (cd "$ui_dir" && npm run build 2>&1) || {
        error "Failed to build frontend."
        warn "The installer will run without the web UI."
        return 0
    }
    success "Frontend built successfully."
}

# ---------------------------------------------------------------------------
# Open browser
# ---------------------------------------------------------------------------
open_browser() {
    local url="$1"

    if [ "${SKIP_BROWSER:-0}" = "1" ]; then
        info "Skipping browser open (SKIP_BROWSER=1)."
        return
    fi

    info "Opening browser at $url ..."

    case "$PLATFORM" in
        darwin)
            open "$url" 2>/dev/null || true
            ;;
        linux)
            if grep -qiE '(microsoft|wsl)' /proc/version 2>/dev/null; then
                # WSL: use Windows browser
                cmd.exe /c start "$url" 2>/dev/null \
                    || powershell.exe -Command "Start-Process '$url'" 2>/dev/null \
                    || true
            elif command -v xdg-open &>/dev/null; then
                xdg-open "$url" 2>/dev/null || true
            elif command -v sensible-browser &>/dev/null; then
                sensible-browser "$url" 2>/dev/null || true
            else
                warn "Could not detect a browser. Please open $url manually."
            fi
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Run the installer
# ---------------------------------------------------------------------------
run_installer() {
    local bin="$INSTALL_DIR/bin/crypto-claw-installer"

    if [ ! -x "$bin" ]; then
        fatal "Installer binary not found at $bin"
    fi

    echo ""
    printf "${BOLD}${GREEN}============================================${NC}\n"
    printf "${BOLD}${GREEN}  Crypto Claw Installer is starting...${NC}\n"
    printf "${BOLD}${GREEN}============================================${NC}\n"
    echo ""
    info "The installer wizard will be available at http://localhost:${INSTALLER_PORT}"
    echo ""

    # Give the server a moment to start, then open the browser
    (
        sleep 2
        open_browser "http://localhost:${INSTALLER_PORT}"
    ) &

    # Run the installer (blocks until user completes or cancels)
    "$bin" || {
        local exit_code=$?
        if [ $exit_code -ne 0 ] && [ $exit_code -ne 130 ]; then
            error "Installer exited with code $exit_code"
            exit $exit_code
        fi
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    echo ""
    detect_platform
    echo ""

    info "Checking prerequisites..."
    check_go
    check_git
    local has_node=true
    check_node || has_node=false
    check_npm  || has_node=false
    check_docker
    echo ""

    info "Install directory: $INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"/{bin,certs,config}
    echo ""

    setup_source
    echo ""

    build_installer
    echo ""

    if [ "$has_node" = true ]; then
        build_frontend
        # Copy built UI into cmd/installer/ui/dist/ for go:embed
        local src_dir="$INSTALL_DIR/src"
        mkdir -p "$src_dir/cmd/installer/ui/dist"
        cp -r "$src_dir/installer/ui/dist/"* "$src_dir/cmd/installer/ui/dist/"
        success "Copied UI dist to cmd/installer/ui/dist/"
        echo ""
        # Rebuild installer with embedded UI
        build_installer
        echo ""
    else
        warn "Skipping frontend build (Node.js/npm not available)."
        echo ""
    fi

    run_installer

    echo ""
    success "Crypto Claw installation complete."
    echo ""
    info "Binaries:      $INSTALL_DIR/bin/"
    info "Configuration: $INSTALL_DIR/config/"
    info "Certificates:  $INSTALL_DIR/certs/"
    echo ""
}

main "$@"
