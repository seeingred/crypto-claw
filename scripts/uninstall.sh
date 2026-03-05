#!/usr/bin/env bash
set -euo pipefail

# Crypto Claw Uninstaller
# Usage: curl -fsSL https://raw.githubusercontent.com/seeingred/crypto-claw/main/scripts/uninstall.sh | bash

# ---------------------------------------------------------------------------
# Colors and formatting
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()    { printf "${CYAN}[INFO]${NC}  %s\n" "$*"; }
success() { printf "${GREEN}[OK]${NC}    %s\n" "$*"; }
warn()    { printf "${YELLOW}[WARN]${NC}  %s\n" "$*"; }
error()   { printf "${RED}[ERROR]${NC} %s\n" "$*" >&2; }
step()    { printf "\n${BOLD}--- %s ---${NC}\n" "$*"; }

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
printf "${BOLD}${RED}"
cat << 'BANNER'

   ____                  _           ____ _
  / ___|_ __ _   _ _ __ | |_ ___    / ___| | __ ___      __
 | |   | '__| | | | '_ \| __/ _ \  | |   | |/ _` \ \ /\ / /
 | |___| |  | |_| | |_) | || (_) | | |___| | (_| |\ V  V /
  \____|_|   \__, | .__/ \__\___/   \____|_|\__,_| \_/\_/
             |___/|_|
  Uninstaller

BANNER
printf "${NC}"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
INSTALL_DIR="${CRYPTO_CLAW_DIR:-$HOME/.crypto-claw}"
CONTAINER_A="crypto-claw-party-a"
CONTAINER_B="crypto-claw-party-b"
IMAGE_A="crypto-claw-party-a"
IMAGE_B="crypto-claw-party-b"
CONFIG_DIR="/etc/crypto-claw"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
prompt_yn() {
    local message="$1"
    local default="${2:-n}"
    local reply
    if [ "$default" = "y" ]; then
        read -rp "$message [Y/n] " reply
        reply="${reply:-y}"
    else
        read -rp "$message [y/N] " reply
        reply="${reply:-n}"
    fi
    [[ "$reply" =~ ^[Yy]$ ]]
}

# Run a command on a remote host via SSH, or locally if host is "local".
run_on() {
    local host="$1"
    shift
    if [ "$host" = "local" ]; then
        eval "$@"
    else
        ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new "$host" "$@"
    fi
}

# ---------------------------------------------------------------------------
# Detect installation mode (local vs remote)
# ---------------------------------------------------------------------------
TARGETS=()

detect_or_prompt_targets() {
    echo ""
    info "Crypto Claw can be installed locally or on remote servers."
    echo ""

    if prompt_yn "Uninstall from local machine?"; then
        TARGETS+=("local")
    fi

    if prompt_yn "Uninstall from remote servers via SSH?"; then
        echo ""
        read -rp "  SSH address for Party A server (e.g. user@host or user@host:port): " server_a
        if [ -n "$server_a" ]; then
            TARGETS+=("$server_a")
        fi

        read -rp "  SSH address for Party B server (e.g. user@host or user@host:port): " server_b
        if [ -n "$server_b" ]; then
            # Avoid adding duplicate if both parties are on the same host
            if [ "$server_b" != "$server_a" ]; then
                TARGETS+=("$server_b")
            else
                info "Party B is on the same host as Party A. Will clean up both on one pass."
            fi
        fi
    fi

    if [ ${#TARGETS[@]} -eq 0 ]; then
        warn "No targets selected. Nothing to do."
        exit 0
    fi
}

# ---------------------------------------------------------------------------
# Stop and remove Docker containers
# ---------------------------------------------------------------------------
remove_containers() {
    local host="$1"

    step "Removing Docker containers on $host"

    for container in "$CONTAINER_A" "$CONTAINER_B"; do
        local running
        running="$(run_on "$host" "docker ps -q -f name='^${container}$'" 2>/dev/null || true)"

        if [ -n "$running" ]; then
            info "Stopping container: $container"
            run_on "$host" "docker stop '$container'" 2>/dev/null && success "Stopped $container" || warn "Could not stop $container"
        fi

        local exists
        exists="$(run_on "$host" "docker ps -aq -f name='^${container}$'" 2>/dev/null || true)"

        if [ -n "$exists" ]; then
            info "Removing container: $container"
            run_on "$host" "docker rm -f '$container'" 2>/dev/null && success "Removed $container" || warn "Could not remove $container"
        else
            info "Container $container does not exist. Skipping."
        fi
    done
}

# ---------------------------------------------------------------------------
# Remove Docker images
# ---------------------------------------------------------------------------
remove_images() {
    local host="$1"

    step "Removing Docker images on $host"

    for image in "$IMAGE_A" "$IMAGE_B"; do
        local image_id
        image_id="$(run_on "$host" "docker images -q '$image'" 2>/dev/null || true)"

        if [ -n "$image_id" ]; then
            info "Removing image: $image"
            run_on "$host" "docker rmi -f '$image'" 2>/dev/null && success "Removed image $image" || warn "Could not remove image $image"
        else
            info "Image $image not found. Skipping."
        fi
    done
}

# ---------------------------------------------------------------------------
# Remove config directory
# ---------------------------------------------------------------------------
remove_config() {
    local host="$1"

    step "Removing configuration on $host"

    local dir_exists
    dir_exists="$(run_on "$host" "test -d '$CONFIG_DIR' && echo yes || echo no" 2>/dev/null || echo "no")"

    if [ "$dir_exists" = "yes" ]; then
        info "Found config directory: $CONFIG_DIR"
        if prompt_yn "  Remove $CONFIG_DIR on $host?"; then
            run_on "$host" "sudo rm -rf '$CONFIG_DIR'" 2>/dev/null \
                && success "Removed $CONFIG_DIR" \
                || warn "Could not remove $CONFIG_DIR (may need elevated permissions)"
        else
            info "Keeping $CONFIG_DIR"
        fi
    else
        info "Config directory $CONFIG_DIR not found on $host. Skipping."
    fi
}

# ---------------------------------------------------------------------------
# Remove database (optional)
# ---------------------------------------------------------------------------
remove_database() {
    local host="$1"

    step "Database cleanup on $host"

    info "Crypto Claw stores key shares and transaction data in PostgreSQL."
    warn "Dropping databases will permanently destroy key shares and audit logs."
    echo ""

    if ! prompt_yn "  Drop Crypto Claw databases (cclaw_a, cclaw_b) on $host?"; then
        info "Keeping databases."
        return
    fi

    echo ""
    printf "  ${RED}${BOLD}WARNING: This action is irreversible.${NC}\n"
    read -rp "  Type 'yes' to confirm database deletion: " confirm
    if [ "$confirm" != "yes" ]; then
        info "Aborted database deletion."
        return
    fi

    info "Attempting to drop databases..."

    # Try dropping via docker exec on a running postgres container first
    local pg_container
    pg_container="$(run_on "$host" "docker ps -q -f name=postgres -f name=crypto-claw-db" 2>/dev/null | head -1 || true)"

    if [ -n "$pg_container" ]; then
        run_on "$host" "docker exec '$pg_container' psql -U postgres -c 'DROP DATABASE IF EXISTS cclaw_a;'" 2>/dev/null \
            && success "Dropped database cclaw_a" \
            || warn "Could not drop cclaw_a"
        run_on "$host" "docker exec '$pg_container' psql -U postgres -c 'DROP DATABASE IF EXISTS cclaw_b;'" 2>/dev/null \
            && success "Dropped database cclaw_b" \
            || warn "Could not drop cclaw_b"
        run_on "$host" "docker exec '$pg_container' psql -U postgres -c \"DROP USER IF EXISTS cclaw;\"" 2>/dev/null \
            && success "Dropped user cclaw" \
            || warn "Could not drop user cclaw"
    else
        # Try local psql
        if run_on "$host" "command -v psql" &>/dev/null; then
            run_on "$host" "psql -U postgres -c 'DROP DATABASE IF EXISTS cclaw_a;'" 2>/dev/null \
                && success "Dropped database cclaw_a" \
                || warn "Could not drop cclaw_a (check PostgreSQL access)"
            run_on "$host" "psql -U postgres -c 'DROP DATABASE IF EXISTS cclaw_b;'" 2>/dev/null \
                && success "Dropped database cclaw_b" \
                || warn "Could not drop cclaw_b (check PostgreSQL access)"
            run_on "$host" "psql -U postgres -c \"DROP USER IF EXISTS cclaw;\"" 2>/dev/null \
                && success "Dropped user cclaw" \
                || warn "Could not drop user cclaw"
        else
            warn "No PostgreSQL client found on $host."
            warn "Manually connect to PostgreSQL and run:"
            echo "    DROP DATABASE IF EXISTS cclaw_a;"
            echo "    DROP DATABASE IF EXISTS cclaw_b;"
            echo "    DROP USER IF EXISTS cclaw;"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Remove local installation directory
# ---------------------------------------------------------------------------
remove_local_install() {
    step "Removing local installation directory"

    if [ -d "$INSTALL_DIR" ]; then
        info "Found installation at: $INSTALL_DIR"
        echo ""
        warn "This directory contains source code, binaries, certificates, and configuration."
        echo ""

        if prompt_yn "  Remove $INSTALL_DIR and all its contents?"; then
            printf "  ${RED}${BOLD}WARNING: This will delete key shares and certificates!${NC}\n"
            read -rp "  Type 'yes' to confirm: " confirm
            if [ "$confirm" = "yes" ]; then
                rm -rf "$INSTALL_DIR"
                success "Removed $INSTALL_DIR"
            else
                info "Aborted. Keeping $INSTALL_DIR."
            fi
        else
            info "Keeping $INSTALL_DIR"
        fi
    else
        info "No local installation found at $INSTALL_DIR"
    fi
}

# ---------------------------------------------------------------------------
# Process a single target
# ---------------------------------------------------------------------------
process_target() {
    local host="$1"

    echo ""
    printf "${BOLD}========================================${NC}\n"
    printf "${BOLD}  Processing: %s${NC}\n" "$host"
    printf "${BOLD}========================================${NC}\n"

    # Verify connectivity for remote hosts
    if [ "$host" != "local" ]; then
        info "Testing SSH connection to $host..."
        if ! ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new "$host" "echo ok" &>/dev/null; then
            error "Cannot connect to $host via SSH. Skipping."
            return
        fi
        success "SSH connection established."
    fi

    # Check if Docker is available on target
    if run_on "$host" "command -v docker" &>/dev/null; then
        remove_containers "$host"
        remove_images "$host"
    else
        info "Docker not found on $host. Skipping container/image cleanup."
    fi

    remove_config "$host"
    remove_database "$host"

    if [ "$host" = "local" ]; then
        remove_local_install
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    detect_or_prompt_targets

    echo ""
    info "Targets to process: ${TARGETS[*]}"

    if ! prompt_yn "Proceed with uninstallation?"; then
        info "Aborted."
        exit 0
    fi

    for target in "${TARGETS[@]}"; do
        process_target "$target"
    done

    echo ""
    printf "${BOLD}${GREEN}============================================${NC}\n"
    printf "${BOLD}${GREEN}  Uninstallation complete.${NC}\n"
    printf "${BOLD}${GREEN}============================================${NC}\n"
    echo ""
    info "If you had custom firewall rules for Crypto Claw, you may want to remove those manually."
    echo ""
}

main "$@"
