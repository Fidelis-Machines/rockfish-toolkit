#!/usr/bin/env bash
# Rockfish Networks / Copyright 2025-2026
# SPDX-License-Identifier: LicenseRef-Rockfish-Commercial
#
# install.sh - Rockfish NDR quick installer
#
#   curl -fsSL https://docs.rockfishndr.com/install.sh | bash
#
# Auto-detects the platform and installs via the best method:
#   - Debian/Ubuntu (amd64)  -> APT repository (recommended; auto-updates)
#   - everything else        -> Docker image
#
# Environment overrides:
#   ROCKFISH_METHOD=apt|docker   force an install method
#   ROCKFISH_VERSION=2026.07.6    pin a specific version (default: latest)
#   ROCKFISH_IMAGE=...            override the Docker image
#                                 (default: rockfishnetworks/toolkit)
#
# The script is safe to re-run; it is idempotent.

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────
REPO_URL="https://repo.rockfishndr.com"
KEYRING_URL="${REPO_URL}/rockfish-archive-keyring.gpg"
KEYRING_PATH="/usr/share/keyrings/rockfish-archive-keyring.gpg"
APT_LIST_PATH="/etc/apt/sources.list.d/rockfish.list"
DOCKER_IMAGE="${ROCKFISH_IMAGE:-rockfishnetworks/toolkit}"
METHOD="${ROCKFISH_METHOD:-}"
VERSION="${ROCKFISH_VERSION:-}"

# ── Pretty output ────────────────────────────────────────────────────────
if [ -t 1 ]; then
    BLUE='\033[0;34m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
else
    BLUE=''; GREEN=''; YELLOW=''; RED=''; NC=''
fi
info()    { printf "${BLUE}==>${NC} %s\n" "$1"; }
success() { printf "${GREEN}==>${NC} %s\n" "$1"; }
warn()    { printf "${YELLOW}Warning:${NC} %s\n" "$1" >&2; }
error()   { printf "${RED}Error:${NC} %s\n" "$1" >&2; exit 1; }

# ── Helpers ──────────────────────────────────────────────────────────────
have() { command -v "$1" >/dev/null 2>&1; }

# Run privileged commands directly when root, else via sudo.
SUDO=""
need_root() {
    [ "$(id -u)" -eq 0 ] && return 0
    have sudo || error "root privileges required (install sudo or run as root)."
    SUDO="sudo"
}

# ── Platform detection ───────────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)  DEB_ARCH="amd64" ;;
    aarch64|arm64) DEB_ARCH="arm64" ;;
    *)             DEB_ARCH="" ;;
esac

is_debian_like() {
    [ "$OS" = "Linux" ] || return 1
    [ -f /etc/debian_version ] && return 0
    have apt-get && return 0
    grep -qiE 'ID(_LIKE)?=.*(debian|ubuntu)' /etc/os-release 2>/dev/null
}

# Decide the method when the caller did not force one.
choose_method() {
    [ -n "$METHOD" ] && return 0
    if is_debian_like && [ "$DEB_ARCH" = "amd64" ]; then
        METHOD="apt"
    elif have docker; then
        METHOD="docker"
        if is_debian_like && [ "$DEB_ARCH" = "arm64" ]; then
            warn "The APT repository currently ships amd64 packages only; using Docker on arm64."
        fi
    elif is_debian_like; then
        # Debian-like but non-amd64 and no docker: let apt produce a precise
        # error rather than guessing.
        METHOD="apt"
        warn "No Docker found and this architecture ($ARCH) may not have APT packages."
    else
        error "Could not auto-detect an install method. Install Docker and re-run, or set ROCKFISH_METHOD=docker."
    fi
}

# ── APT installation ─────────────────────────────────────────────────────
install_apt() {
    have curl || error "curl is required for the APT install. Install curl and re-run."
    need_root
    [ "$DEB_ARCH" = "amd64" ] || warn "APT packages are published for amd64; '$DEB_ARCH' may not resolve."

    info "Adding the Rockfish signing key -> $KEYRING_PATH"
    $SUDO install -d -m 0755 "$(dirname "$KEYRING_PATH")"
    $SUDO curl -fsSLo "$KEYRING_PATH" "$KEYRING_URL" \
        || error "Failed to download the signing key from $KEYRING_URL"

    info "Adding the APT source -> $APT_LIST_PATH"
    printf 'deb [arch=amd64 signed-by=%s] %s stable main\n' "$KEYRING_PATH" "$REPO_URL" \
        | $SUDO tee "$APT_LIST_PATH" >/dev/null

    info "Updating package lists"
    $SUDO apt-get update

    if [ -n "$VERSION" ]; then
        info "Installing rockfish=$VERSION"
        $SUDO apt-get install -y "rockfish=$VERSION"
    else
        info "Installing rockfish (latest)"
        $SUDO apt-get install -y rockfish
    fi

    success "Rockfish NDR installed via APT."
    printf '\n'
    info "Next steps:"
    echo "  sudo systemctl daemon-reload"
    echo "  sudo systemctl enable --now rockfish rockfish-report"
    echo "  rockfish --version"
    echo
    echo "  Update later with: sudo apt-get update && sudo apt-get upgrade rockfish"
}

# ── Docker installation ──────────────────────────────────────────────────
install_docker() {
    have docker || error "Docker is required for this method but was not found. Install Docker and re-run."
    local ref="${DOCKER_IMAGE}:${VERSION:-latest}"
    info "Pulling $ref"
    docker pull "$ref" || error "Failed to pull $ref"

    success "Rockfish NDR image pulled: $ref"
    printf '\n'
    info "Run it (ingest mode):"
    cat <<EOF
  docker run -d --name rockfish \\
    -v /opt/rockfish/etc:/opt/rockfish/etc:ro \\
    -v /data/rockfish:/data/rockfish \\
    -p 3000:3000 -p 8082:8082 \\
    $ref \\
    rockfish ingest --socket /var/run/suricata/eve.sock

  Verify: docker run --rm $ref rockfish --version
EOF
}

# ── Main ─────────────────────────────────────────────────────────────────
main() {
    info "Rockfish NDR installer"
    info "Platform: $OS/$ARCH${VERSION:+ | version: $VERSION}"

    choose_method
    case "$METHOD" in
        apt)    info "Method: APT repository"; install_apt ;;
        docker) info "Method: Docker";         install_docker ;;
        *)      error "Unknown ROCKFISH_METHOD='$METHOD' (expected 'apt' or 'docker')." ;;
    esac

    printf '\n'
    success "Done. Docs: https://docs.rockfishndr.com/getting-started/installation.html"
}

main "$@"
