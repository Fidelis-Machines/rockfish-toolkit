#!/usr/bin/env bash
# Rockfish Networks / Copyright 2025-2026
# SPDX-License-Identifier: LicenseRef-Rockfish-Commercial
#
# ============================================================================
#  install.sh — Rockfish NDR quick installer & verifier
# ============================================================================
#
#  This is the AUTHORITATIVE copy, maintained in the rockfish-toolkit repo at
#  install/install.sh. A synced copy is served at https://docs.rockfishndr.com/
#  install.sh for the branded one-liner below — when you change this script,
#  update that mirror (ndr/docs/src/install.sh in the rockfish repo) and
#  redeploy the docs image.
#
#  USAGE
#  -----
#    # Install (default):
#    curl -fsSL https://docs.rockfishndr.com/install.sh | bash
#
#    # Verify an existing install:
#    curl -fsSL https://docs.rockfishndr.com/install.sh | bash -s -- verify
#
#    # Or, after cloning the toolkit:
#    ./install.sh            # install
#    ./install.sh verify     # run diagnostics
#    ./install.sh help       # show usage
#
#  MODES
#  -----
#    install  (default)  Add the APT repo (Debian/Ubuntu amd64) and install the
#                        `rockfish` package, or pull the Docker image elsewhere.
#    verify              Run read-only diagnostics and report whether the
#                        installation is correct and complete. Exits non-zero if
#                        any check FAILs. Changes nothing on disk.
#
#  ENVIRONMENT OVERRIDES
#  ---------------------
#    ROCKFISH_METHOD=apt|docker   Force an install method (default: auto-detect —
#                                 APT on Debian/Ubuntu amd64, Docker otherwise).
#    ROCKFISH_VERSION=2026.07.6   Pin a specific version (default: latest).
#    ROCKFISH_IMAGE=...           Override the Docker image
#                                 (default: rockfishnetworks/toolkit).
#
#  WHAT THE INSTALL DOES (APT path)
#  --------------------------------
#    1. Downloads the repo signing key to
#       /usr/share/keyrings/rockfish-archive-keyring.gpg
#    2. Writes the APT source to /etc/apt/sources.list.d/rockfish.list
#    3. `apt-get update` then `apt-get install rockfish`
#    The package installs to /opt/rockfish and ships systemd units, config
#    examples, and the version-matched DuckDB extensions (inet, httpfs).
#
#  The script is safe to re-run; both modes are idempotent.
# ============================================================================

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────
REPO_URL="https://repo.rockfishndr.com"
KEYRING_URL="${REPO_URL}/rockfish-archive-keyring.gpg"
KEYRING_PATH="/usr/share/keyrings/rockfish-archive-keyring.gpg"
APT_LIST_PATH="/etc/apt/sources.list.d/rockfish.list"
DOCKER_IMAGE="${ROCKFISH_IMAGE:-rockfishnetworks/toolkit}"
METHOD="${ROCKFISH_METHOD:-}"
VERSION="${ROCKFISH_VERSION:-}"

# Filesystem layout the .deb installs into (used by verify).
PREFIX="/opt/rockfish"
BIN="${PREFIX}/bin/rockfish"
EXT_DIR="${PREFIX}/shared/extensions"          # {ver}/{platform}/{name}.duckdb_extension
DATA_DIR="/var/lib/rockfish"

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
    echo "  Verify:  curl -fsSL https://docs.rockfishndr.com/install.sh | bash -s -- verify"
    echo "  Update:  sudo apt-get update && sudo apt-get upgrade rockfish"
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

# ── Verify mode ──────────────────────────────────────────────────────────
# Read-only diagnostics: confirm the installation is present, runnable, and
# complete. Each check prints PASS / WARN / FAIL; the run exits non-zero if any
# check FAILs. WARN means "not wrong, but worth knowing" (e.g. service not yet
# enabled). Nothing here writes to disk.
PASS_N=0; WARN_N=0; FAIL_N=0
pass() { printf "  ${GREEN}[PASS]${NC} %s\n" "$1"; PASS_N=$((PASS_N+1)); }
vwarn(){ printf "  ${YELLOW}[WARN]${NC} %s\n" "$1"; WARN_N=$((WARN_N+1)); }
fail() { printf "  ${RED}[FAIL]${NC} %s\n" "$1"; FAIL_N=$((FAIL_N+1)); }

verify_apt_install() {
    # 1. Binary present + executable
    if [ -x "$BIN" ]; then
        pass "binary present: $BIN"
    else
        fail "binary missing: $BIN (package not installed?)"
        return
    fi

    # 2. Binary runs (this also exercises the libduckdb dynamic link)
    local ver
    if ver="$("$BIN" --version 2>/dev/null)"; then
        pass "binary runs: $ver"
    else
        fail "'$BIN --version' failed — likely a missing/mismatched libduckdb. Install libduckdb and retry."
    fi

    # 3. libduckdb resolves (dynamic dependency the engine needs at runtime)
    if have ldd; then
        if ldd "$BIN" 2>/dev/null | grep -qi 'libduckdb.*not found'; then
            fail "libduckdb not found by the dynamic linker (customer-provided; install it and run ldconfig)."
        elif ldd "$BIN" 2>/dev/null | grep -qi 'libduckdb'; then
            pass "libduckdb resolves for the dynamic linker"
        else
            vwarn "could not confirm libduckdb linkage via ldd"
        fi
    fi

    # 4. Bundled DuckDB extensions (inet, httpfs) present for the installed ver
    if [ -d "$EXT_DIR" ]; then
        local found_inet found_httpfs
        found_inet="$(find "$EXT_DIR" -name 'inet.duckdb_extension' 2>/dev/null | head -1)"
        found_httpfs="$(find "$EXT_DIR" -name 'httpfs.duckdb_extension' 2>/dev/null | head -1)"
        [ -n "$found_inet" ]   && pass "DuckDB extension bundled: inet"   || vwarn "DuckDB 'inet' extension not bundled under $EXT_DIR (LOAD inet will need network)"
        [ -n "$found_httpfs" ] && pass "DuckDB extension bundled: httpfs" || vwarn "DuckDB 'httpfs' extension not bundled under $EXT_DIR"
    else
        vwarn "extension dir absent: $EXT_DIR (offline LOAD of inet/httpfs unavailable)"
    fi

    # 5. systemd units present + state
    if have systemctl; then
        local u
        for u in rockfish rockfish-report; do
            if systemctl list-unit-files "${u}.service" 2>/dev/null | grep -q "${u}.service"; then
                if systemctl is-enabled "${u}.service" >/dev/null 2>&1; then
                    pass "systemd unit ${u}.service present (enabled)"
                else
                    vwarn "systemd unit ${u}.service present but not enabled (enable with: systemctl enable --now ${u})"
                fi
            else
                vwarn "systemd unit ${u}.service not registered (run: systemctl daemon-reload)"
            fi
        done
    else
        vwarn "systemctl not available — skipping service checks"
    fi

    # 6. Config directory + example
    if [ -d "${PREFIX}/etc" ]; then
        if [ -f "${PREFIX}/etc/rockfish.yaml" ]; then
            pass "config present: ${PREFIX}/etc/rockfish.yaml"
        elif [ -f "${PREFIX}/etc/rockfish.yaml.example" ]; then
            vwarn "no rockfish.yaml yet — copy from ${PREFIX}/etc/rockfish.yaml.example"
        else
            vwarn "no config or example found in ${PREFIX}/etc"
        fi
    else
        vwarn "config dir absent: ${PREFIX}/etc"
    fi

    # 7. Data directory
    [ -d "$DATA_DIR" ] && pass "data dir present: $DATA_DIR" || vwarn "data dir absent: $DATA_DIR (created on first run)"

    # 8. APT wiring (so future upgrades work)
    [ -f "$KEYRING_PATH" ] && pass "APT signing key installed" || vwarn "APT signing key missing: $KEYRING_PATH"
    [ -f "$APT_LIST_PATH" ] && pass "APT source configured"    || vwarn "APT source missing: $APT_LIST_PATH"
}

verify_docker_install() {
    have docker || { fail "docker not found — nothing to verify for the Docker method"; return; }
    local ref="${DOCKER_IMAGE}:${VERSION:-latest}"
    if docker image inspect "$ref" >/dev/null 2>&1; then
        pass "image present locally: $ref"
    else
        vwarn "image not pulled locally: $ref (run the installer, or 'docker pull $ref')"
    fi
    if docker run --rm "$ref" rockfish --version >/dev/null 2>&1; then
        pass "container runs: $(docker run --rm "$ref" rockfish --version 2>/dev/null)"
    else
        vwarn "could not run 'rockfish --version' in $ref"
    fi
}

run_verify() {
    info "Rockfish NDR — installation diagnostics"
    info "Platform: $OS/$ARCH"
    printf '\n'

    # Decide what to verify: prefer an on-disk APT install; fall back to Docker.
    if [ -e "$BIN" ] || { is_debian_like && [ "${METHOD:-apt}" != "docker" ]; }; then
        info "Checking APT / host install ($PREFIX):"
        verify_apt_install
    fi
    if have docker && { [ ! -x "$BIN" ] || [ "${METHOD:-}" = "docker" ]; }; then
        printf '\n'; info "Checking Docker image (${DOCKER_IMAGE}):"
        verify_docker_install
    fi

    printf '\n'
    printf "Summary: ${GREEN}%d passed${NC}, ${YELLOW}%d warnings${NC}, ${RED}%d failed${NC}\n" \
        "$PASS_N" "$WARN_N" "$FAIL_N"
    if [ "$FAIL_N" -gt 0 ]; then
        error "Installation incomplete — see FAIL items above."
    fi
    success "Installation looks correct and complete."
}

# ── Install driver ───────────────────────────────────────────────────────
run_install() {
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

usage() {
    cat <<EOF
Rockfish NDR installer

Usage:
  install.sh [install]     Install Rockfish NDR (default)
  install.sh verify        Run read-only diagnostics on an existing install
  install.sh help          Show this message

Environment:
  ROCKFISH_METHOD=apt|docker   Force the install method (default: auto-detect)
  ROCKFISH_VERSION=X.Y.Z       Pin a version (default: latest)
  ROCKFISH_IMAGE=...           Override the Docker image

Examples:
  curl -fsSL https://docs.rockfishndr.com/install.sh | bash
  curl -fsSL https://docs.rockfishndr.com/install.sh | bash -s -- verify
EOF
}

# ── Entry point ──────────────────────────────────────────────────────────
main() {
    case "${1:-install}" in
        install|"")      run_install ;;
        verify|--verify) run_verify ;;
        help|-h|--help)  usage ;;
        *) error "Unknown command '$1' (expected: install | verify | help)." ;;
    esac
}

main "$@"
