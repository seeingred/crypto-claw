#!/usr/bin/env bash
set -euo pipefail

# Crypto Claw Uninstaller
# Handles both Docker-based local installs and remote server installs.

# ---------------------------------------------------------------------------
# Colors
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
# Constants (must match deploy.go)
# ---------------------------------------------------------------------------
CONTAINER_A="crypto-claw-party-a"
CONTAINER_B="crypto-claw-party-b"
CONTAINER_PG="crypto-claw-postgres"
LOCAL_CONFIG_DIR="$HOME/.crypto-claw"
REMOTE_CONFIG_DIR="/etc/crypto-claw"
DB_USER="crypto_claw"
DB_A="crypto_claw_a"
DB_B="crypto_claw_b"

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

run_on() {
    local host="$1"; shift
    if [ "$host" = "local" ]; then
        eval "$@"
    else
        ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new "$host" "$@"
    fi
}

# ---------------------------------------------------------------------------
# Stop and remove Docker containers (party-a, party-b, postgres)
# ---------------------------------------------------------------------------
remove_containers() {
    local host="$1"
    step "Removing Docker containers on $host"

    for container in "$CONTAINER_A" "$CONTAINER_B" "$CONTAINER_PG"; do
        local exists
        exists="$(run_on "$host" "docker ps -aq -f name='^${container}$'" 2>/dev/null || true)"
        if [ -n "$exists" ]; then
            info "Stopping and removing: $container"
            run_on "$host" "docker stop '$container' 2>/dev/null; docker rm -f '$container' 2>/dev/null" \
                && success "Removed $container" \
                || warn "Could not remove $container"
        else
            info "Container $container not found. Skipping."
        fi
    done

    # Kill legacy bare processes (pre-Docker installs).
    if [ "$host" = "local" ]; then
        for port in 8080 9000; do
            local pids
            pids="$(lsof -ti ":$port" 2>/dev/null || true)"
            if [ -n "$pids" ]; then
                info "Killing process on port $port (legacy)"
                echo "$pids" | xargs kill 2>/dev/null || true
            fi
        done
    fi
}

# ---------------------------------------------------------------------------
# Remove Docker images
# ---------------------------------------------------------------------------
remove_images() {
    local host="$1"
    step "Removing Docker images on $host"

    for image in "$CONTAINER_A" "$CONTAINER_B"; do
        local image_id
        image_id="$(run_on "$host" "docker images -q '${image}'" 2>/dev/null || true)"
        if [ -n "$image_id" ]; then
            info "Removing image: $image"
            run_on "$host" "docker rmi -f '$image'" 2>/dev/null \
                && success "Removed image $image" \
                || warn "Could not remove image $image"
        else
            info "Image $image not found. Skipping."
        fi
    done
}

# ---------------------------------------------------------------------------
# Remove config directories
# ---------------------------------------------------------------------------
remove_config() {
    local host="$1"
    step "Removing configuration on $host"

    # Local mode uses ~/.crypto-claw, remote uses /etc/crypto-claw.
    local dirs=("$REMOTE_CONFIG_DIR")
    if [ "$host" = "local" ]; then
        dirs=("$LOCAL_CONFIG_DIR")
    fi

    for dir in "${dirs[@]}"; do
        local dir_exists
        dir_exists="$(run_on "$host" "test -d '$dir' && echo yes || echo no" 2>/dev/null || echo "no")"
        if [ "$dir_exists" = "yes" ]; then
            info "Found config directory: $dir"
            if prompt_yn "  Remove $dir?"; then
                run_on "$host" "rm -rf '$dir'" 2>/dev/null \
                    && success "Removed $dir" \
                    || { run_on "$host" "sudo rm -rf '$dir'" 2>/dev/null \
                        && success "Removed $dir (sudo)" \
                        || warn "Could not remove $dir"; }
            else
                info "Keeping $dir"
            fi
        else
            info "Config directory $dir not found. Skipping."
        fi
    done
}

# ---------------------------------------------------------------------------
# Remove databases
# ---------------------------------------------------------------------------
remove_database() {
    local host="$1"
    step "Database cleanup on $host"

    info "Crypto Claw databases: $DB_A, $DB_B (user: $DB_USER)"
    warn "Dropping databases will permanently destroy key shares and audit logs."
    echo ""

    if ! prompt_yn "  Drop Crypto Claw databases on $host?"; then
        info "Keeping databases."
        return
    fi

    printf "  ${RED}${BOLD}WARNING: This action is irreversible.${NC}\n"
    read -rp "  Type 'yes' to confirm: " confirm
    if [ "$confirm" != "yes" ]; then
        info "Aborted database deletion."
        return
    fi

    info "Dropping databases..."

    # Try via our Docker postgres container first.
    local pg_running
    pg_running="$(run_on "$host" "docker ps -q -f name='^${CONTAINER_PG}$'" 2>/dev/null || true)"

    if [ -n "$pg_running" ]; then
        info "Using Docker postgres container ($CONTAINER_PG)"
        for db in "$DB_A" "$DB_B"; do
            run_on "$host" "docker exec '$CONTAINER_PG' psql -U '$DB_USER' -c 'DROP DATABASE IF EXISTS $db;'" 2>/dev/null \
                && success "Dropped $db" \
                || warn "Could not drop $db"
        done
        return
    fi

    # Try any other running postgres container.
    local any_pg
    any_pg="$(run_on "$host" "docker ps -q -f ancestor=postgres" 2>/dev/null | head -1 || true)"
    if [ -n "$any_pg" ]; then
        info "Using postgres container $any_pg"
        for db in "$DB_A" "$DB_B"; do
            run_on "$host" "docker exec '$any_pg' psql -U postgres -c 'DROP DATABASE IF EXISTS $db;'" 2>/dev/null \
                && success "Dropped $db" \
                || warn "Could not drop $db"
        done
        run_on "$host" "docker exec '$any_pg' psql -U postgres -c \"DROP USER IF EXISTS $DB_USER;\"" 2>/dev/null \
            && success "Dropped user $DB_USER" \
            || warn "Could not drop user $DB_USER"
        return
    fi

    # Try host psql.
    if run_on "$host" "command -v psql" &>/dev/null; then
        info "Using host psql"
        for db in "$DB_A" "$DB_B"; do
            run_on "$host" "psql -c 'DROP DATABASE IF EXISTS $db;' postgres" 2>/dev/null \
                && success "Dropped $db" \
                || warn "Could not drop $db"
        done
        run_on "$host" "psql -c \"DROP USER IF EXISTS $DB_USER;\" postgres" 2>/dev/null \
            && success "Dropped user $DB_USER" \
            || warn "Could not drop user $DB_USER"
        return
    fi

    warn "No PostgreSQL client found on $host."
    warn "Manually run:"
    echo "    DROP DATABASE IF EXISTS $DB_A;"
    echo "    DROP DATABASE IF EXISTS $DB_B;"
    echo "    DROP USER IF EXISTS $DB_USER;"
}

# ---------------------------------------------------------------------------
# Detect targets
# ---------------------------------------------------------------------------
TARGETS=()

detect_or_prompt_targets() {
    echo ""
    info "Crypto Claw can be installed locally or on remote servers."
    echo ""

    if prompt_yn "Uninstall from local machine?" "y"; then
        TARGETS+=("local")
    fi

    if prompt_yn "Uninstall from remote servers via SSH?"; then
        echo ""
        read -rp "  SSH address for Party A (e.g. user@host): " server_a
        [ -n "$server_a" ] && TARGETS+=("$server_a")

        read -rp "  SSH address for Party B (e.g. user@host): " server_b
        if [ -n "$server_b" ] && [ "$server_b" != "$server_a" ]; then
            TARGETS+=("$server_b")
        fi
    fi

    if [ ${#TARGETS[@]} -eq 0 ]; then
        warn "No targets selected. Nothing to do."
        exit 0
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

    if [ "$host" != "local" ]; then
        info "Testing SSH connection to $host..."
        if ! ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new "$host" "echo ok" &>/dev/null; then
            error "Cannot connect to $host via SSH. Skipping."
            return
        fi
        success "SSH connection established."
    fi

    if run_on "$host" "command -v docker" &>/dev/null; then
        remove_containers "$host"
        remove_images "$host"
    else
        info "Docker not found on $host. Skipping container/image cleanup."
    fi

    remove_config "$host"
    remove_database "$host"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    detect_or_prompt_targets

    echo ""
    info "Targets: ${TARGETS[*]}"

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
}

main "$@"
