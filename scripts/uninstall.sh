#!/usr/bin/env bash
set -euo pipefail

# Crypto Claw Uninstaller
# Usage: curl -fsSL https://raw.githubusercontent.com/seeingred/crypto-claw/main/scripts/uninstall.sh | bash

INSTALL_DIR="${CRYPTO_CLAW_DIR:-$HOME/.crypto-claw}"

echo "╔══════════════════════════════════════╗"
echo "║      Crypto Claw Uninstaller         ║"
echo "╚══════════════════════════════════════╝"
echo ""

# Check for running Docker containers
if command -v docker &>/dev/null; then
    PARTY_A_CONTAINER=$(docker ps -q -f name=crypto-claw-party-a 2>/dev/null || true)
    PARTY_B_CONTAINER=$(docker ps -q -f name=crypto-claw-party-b 2>/dev/null || true)

    if [ -n "$PARTY_A_CONTAINER" ] || [ -n "$PARTY_B_CONTAINER" ]; then
        echo "Found running Crypto Claw containers."
        read -rp "Stop and remove containers? [y/N] " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            [ -n "$PARTY_A_CONTAINER" ] && docker stop crypto-claw-party-a && docker rm crypto-claw-party-a
            [ -n "$PARTY_B_CONTAINER" ] && docker stop crypto-claw-party-b && docker rm crypto-claw-party-b
            echo "Containers removed."
        fi
    fi

    # Remove images
    if docker images -q "crypto-claw-party-a" 2>/dev/null | grep -q .; then
        read -rp "Remove Docker images? [y/N] " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            docker rmi crypto-claw-party-a crypto-claw-party-b 2>/dev/null || true
            echo "Images removed."
        fi
    fi
fi

# Remove installation directory
if [ -d "$INSTALL_DIR" ]; then
    echo ""
    echo "Installation directory: $INSTALL_DIR"
    read -rp "Remove installation directory and all data? [y/N] " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        echo ""
        echo "WARNING: This will delete key shares and certificates!"
        read -rp "Are you sure? Type 'yes' to confirm: " final
        if [ "$final" = "yes" ]; then
            rm -rf "$INSTALL_DIR"
            echo "Installation directory removed."
        else
            echo "Aborted."
        fi
    fi
else
    echo "No installation found at $INSTALL_DIR"
fi

echo ""
echo "Note: PostgreSQL databases on remote servers are not affected."
echo "To clean up databases, connect to each server and drop the crypto-claw database."
echo ""
echo "Uninstall complete."
