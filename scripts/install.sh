#!/usr/bin/env bash
set -euo pipefail

# Crypto Claw Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/seeingred/crypto-claw/main/scripts/install.sh | bash

REPO="seeingred/crypto-claw"
INSTALL_DIR="${CRYPTO_CLAW_DIR:-$HOME/.crypto-claw}"

echo "╔══════════════════════════════════════╗"
echo "║       Crypto Claw Installer          ║"
echo "║   MPC-TSS Crypto Signing Service     ║"
echo "╚══════════════════════════════════════╝"
echo ""

# Detect OS and architecture
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

echo "Detected: ${OS}/${ARCH}"
echo "Install directory: ${INSTALL_DIR}"
echo ""

# Create install directory
mkdir -p "$INSTALL_DIR"/{bin,certs,config}

# Check for Go
if command -v go &>/dev/null; then
    echo "Go found: $(go version)"
else
    echo "Error: Go is required. Install from https://go.dev/dl/"
    exit 1
fi

# Check for Docker
if command -v docker &>/dev/null; then
    echo "Docker found: $(docker --version)"
else
    echo "Warning: Docker not found. You'll need it for deployment."
fi

# Clone or update repository
if [ -d "$INSTALL_DIR/src" ]; then
    echo "Updating existing installation..."
    cd "$INSTALL_DIR/src"
    git pull --ff-only
else
    echo "Cloning repository..."
    git clone "https://github.com/${REPO}.git" "$INSTALL_DIR/src"
    cd "$INSTALL_DIR/src"
fi

# Build binaries
echo ""
echo "Building binaries..."
CGO_ENABLED=0 go build -ldflags="-s -w" -o "$INSTALL_DIR/bin/party-a" ./cmd/party-a
CGO_ENABLED=0 go build -ldflags="-s -w" -o "$INSTALL_DIR/bin/party-b" ./cmd/party-b
CGO_ENABLED=0 go build -ldflags="-s -w" -o "$INSTALL_DIR/bin/installer" ./cmd/installer

echo ""
echo "Build complete!"
echo ""
echo "Binaries installed to: $INSTALL_DIR/bin/"
echo ""
echo "Next steps:"
echo "  1. Run the installer wizard:"
echo "     $INSTALL_DIR/bin/installer"
echo ""
echo "  2. Or manually configure and start:"
echo "     $INSTALL_DIR/bin/party-a -config config.json"
echo "     $INSTALL_DIR/bin/party-b -config config.json"
echo ""
echo "For Docker deployment, use docker/Dockerfile.party-a and docker/Dockerfile.party-b"
