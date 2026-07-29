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
#                        `rockfish` package (or pull the Docker image elsewhere).
#                        On APT hosts it then PROMPTS to set up the two systemd
#                        services, and finishes by running `verify`.
#    verify              Run read-only diagnostics and report whether the
#                        installation is correct and complete. Exits non-zero if
#                        any check FAILs. Changes nothing on disk.
#
#  SYSTEMD SERVICES (APT installs)
#  -------------------------------
#    rockfish.service         detection — collects Suricata EVE records,
#                             enriches them, and stores them as Parquet.
#    rockfish-report.service  reporting — regenerates + serves the dashboard
#                             every ROCKFISH_REPORT_INTERVAL_MIN minutes (10).
#  Both are `systemctl enable`d (start on boot) and run with
#  WorkingDirectory=/var/run/rockfish (transient data on tmpfs). The installer
#  asks before enabling them (skip the prompt with ROCKFISH_SERVICES=yes|no).
#
#  ENVIRONMENT OVERRIDES
#  ---------------------
#    ROCKFISH_METHOD=apt|docker      Force an install method (default: auto —
#                                    APT on Debian/Ubuntu amd64, else Docker).
#    ROCKFISH_VERSION=2026.07.6      Pin a specific version (default: latest).
#    ROCKFISH_IMAGE=...              Override the Docker image
#                                    (default: rockfishnetworks/toolkit).
#    ROCKFISH_SERVICES=yes|no        Set up the systemd services unattended
#                                    (default: prompt).
#    ROCKFISH_REPORT_INTERVAL_MIN=N  Report cadence in minutes (default: 10).
#    ROCKFISH_LIBDUCKDB_VERSION=X.Y.Z  Override the libduckdb version installed
#                                    (default: inferred from bundled extensions).
#
#  WHAT THE INSTALL DOES (APT path)
#  --------------------------------
#    1. Downloads the repo signing key to
#       /usr/share/keyrings/rockfish-archive-keyring.gpg
#    2. Writes the APT source to /etc/apt/sources.list.d/rockfish.list
#    3. `apt-get update`, then install rockfish — a clean `--reinstall` if an
#       existing install is detected (package db, or ${BIN}), else a plain install.
#    4. Installs the matching libduckdb into /usr/local/lib (the .deb does not
#       ship it) unless one is already present.
#    5. Creates the parquet storage dir /opt/rockfish/data and points the
#       config's output.dir at it (unless already customized).
#    6. Optionally enables the services, then runs verify and reminds you to
#       drop in the license and restart.
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

# systemd services. ROCKFISH_SERVICES forces the choice non-interactively
# (yes/no); left unset, the installer prompts. The report regenerates every
# ROCKFISH_REPORT_INTERVAL_MIN minutes.
SERVICES="${ROCKFISH_SERVICES:-}"
REPORT_INTERVAL_MIN="${ROCKFISH_REPORT_INTERVAL_MIN:-10}"
SERVICES_ENABLED=0   # set to 1 once enable_services runs

# The engine dynamically links libduckdb, which the .deb does NOT ship (it is
# version-locked to the DuckDB the release was built against). The installer
# fetches the matching libduckdb unless one is already present. Override the
# version with ROCKFISH_LIBDUCKDB_VERSION; DUCKDB_FALLBACK is used only if the
# version can't be inferred from the bundled extensions.
LIBDUCKDB_VERSION="${ROCKFISH_LIBDUCKDB_VERSION:-}"
DUCKDB_FALLBACK="1.4.4"

# Filesystem layout the .deb installs into (used by verify).
PREFIX="/opt/rockfish"
BIN="${PREFIX}/bin/rockfish"
EXT_DIR="${PREFIX}/shared/extensions"          # {ver}/{platform}/{name}.duckdb_extension
DATA_DIR="/var/lib/rockfish"
LICENSE_FILE="${PREFIX}/etc/rockfish_license.json"  # where to drop the license
DATA_STORE="${PREFIX}/data"                          # default parquet hive dir
CONFIG_FILE="${PREFIX}/etc/rockfish.yaml"
RUNTIME_DIR="/var/run/rockfish"                      # transient runtime data (tmpfs)
REPORT_DROPIN="/etc/systemd/system/rockfish-report.service.d/interval.conf"
DETECT_DROPIN="/etc/systemd/system/rockfish.service.d/runtime.conf"

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

    local pkg="rockfish"
    [ -n "$VERSION" ] && pkg="rockfish=$VERSION"

    # Existing install? Reinstall cleanly. Fresh box? Plain install.
    if rockfish_installed; then
        info "Existing Rockfish install detected — reinstalling ${pkg} cleanly"
        $SUDO apt-get install -y --reinstall "$pkg"
    else
        info "No existing install — installing ${pkg}"
        $SUDO apt-get install -y "$pkg"
    fi

    success "Rockfish NDR package installed via APT."
}

# True if Rockfish is already installed — by the package database (authoritative)
# or the binary on disk at ${BIN} (/opt/rockfish/bin/rockfish, the .deb layout).
rockfish_installed() {
    dpkg-query -W -f='${Status}' rockfish 2>/dev/null | grep -q "install ok installed" && return 0
    [ -x "$BIN" ]
}

# ── libduckdb runtime dependency ─────────────────────────────────────────
# Infer the required DuckDB version from the bundled extension dir — extensions
# are version-locked to libduckdb, so the version subdir (e.g. v1.4.4) is the
# exact runtime version needed.
detect_duckdb_version() {
    local d
    d="$(find "$EXT_DIR" -maxdepth 1 -type d -name 'v*' 2>/dev/null | sort -V | tail -1)"
    [ -n "$d" ] && basename "$d" | sed 's/^v//'
}

# Install the matching libduckdb into /usr/local/lib unless one is already
# present. Best-effort: on an air-gapped host the download fails and we print
# manual instructions rather than aborting.
install_libduckdb() {
    have ldconfig && ldconfig -p 2>/dev/null | grep -qi 'libduckdb' && {
        info "libduckdb already present — leaving it in place."; return 0; }

    local ver="$LIBDUCKDB_VERSION"
    [ -z "$ver" ] && ver="$(detect_duckdb_version)"
    [ -z "$ver" ] && ver="$DUCKDB_FALLBACK"

    local asset="libduckdb-linux-amd64.zip"
    [ "$DEB_ARCH" = "arm64" ] && asset="libduckdb-linux-arm64.zip"
    local url="https://github.com/duckdb/duckdb/releases/download/v${ver}/${asset}"

    need_root
    have unzip || $SUDO apt-get install -y unzip >/dev/null 2>&1 || true
    have unzip || { warn "unzip not available — cannot install libduckdb ${ver}. Install it and libduckdb manually."; return 0; }

    info "Installing runtime libduckdb ${ver} -> /usr/local/lib (matches the bundled extensions)"
    local tmp; tmp="$(mktemp /tmp/rf-libduckdb.XXXXXX.zip)"
    if curl -fsSL "$url" -o "$tmp" 2>/dev/null; then
        $SUDO unzip -o -q "$tmp" -d /usr/local/lib/ && $SUDO ldconfig
        rm -f "$tmp"
        success "libduckdb ${ver} installed."
    else
        rm -f "$tmp"
        warn "Could not download libduckdb ${ver} from ${url}."
        warn "Air-gapped host? Install libduckdb ${ver} into /usr/local/lib and run ldconfig, then: install.sh verify"
    fi
}

# ── Parquet storage directory ────────────────────────────────────────────
# Default installs store Parquet under /opt/rockfish/data. Create it (owned by
# the service user) and point the config's output.dir at it — but only when the
# config still holds the packaged default, so a customized dir is never clobbered.
setup_storage_dir() {
    need_root
    info "Parquet storage directory: ${DATA_STORE}"
    $SUDO install -d -m 0755 "$DATA_STORE"
    id rockfish >/dev/null 2>&1 && $SUDO chown -R rockfish:rockfish "$DATA_STORE" || true

    if [ -f "$CONFIG_FILE" ] && grep -qE '^[[:space:]]*dir:[[:space:]]*/var/lib/rockfish/parquet[[:space:]]*$' "$CONFIG_FILE"; then
        $SUDO sed -i -E "s#^([[:space:]]*)dir:[[:space:]]*/var/lib/rockfish/parquet[[:space:]]*\$#\1dir: ${DATA_STORE}#" "$CONFIG_FILE"
        info "Set output.dir -> ${DATA_STORE} in ${CONFIG_FILE}"
    elif [ -f "$CONFIG_FILE" ]; then
        info "Leaving existing output.dir in ${CONFIG_FILE} unchanged (not the packaged default)."
    fi
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

# ── systemd services ─────────────────────────────────────────────────────
# The package ships two units:
#   rockfish.service         detection engine (`rockfish detect`) — collects
#                            Suricata EVE records, enriches them, and stores
#                            them as Parquet.
#   rockfish-report.service  reporting — regenerates and serves the dashboard,
#                            every REPORT_INTERVAL_MIN minutes.

# Ask whether to set up the services. Works under `curl | bash` by reading the
# terminal (/dev/tty), since stdin is the piped script. ROCKFISH_SERVICES
# (yes/no) skips the prompt; with no terminal and no override, default to no.
want_services() {
    case "$SERVICES" in
        1|y|Y|yes|YES|true)  return 0 ;;
        0|n|N|no|NO|false)   info "Skipping service setup (ROCKFISH_SERVICES=$SERVICES)."; return 1 ;;
    esac
    have systemctl || { info "systemd not present — skipping service setup."; return 1; }
    # Prompt on the terminal (stdin is the piped script under `curl | bash`).
    # Only a SUCCESSFUL read counts as an answer — an empty line (Enter) means
    # yes, but EOF/no-tty falls through to skip so we never auto-enable
    # non-interactively.
    if [ -r /dev/tty ]; then
        local ans
        printf "Install and enable the detection + reporting systemd services now? [Y/n] " > /dev/tty
        if read -r ans < /dev/tty; then
            case "$ans" in [Nn]*) return 1 ;; *) return 0 ;; esac
        fi
    fi
    info "No interactive input — skipping services (set ROCKFISH_SERVICES=yes to enable unattended)."
    return 1
}

enable_services() {
    have systemctl || { warn "systemd not present — cannot enable services."; return 0; }
    need_root

    # Detection service drop-in: run from the transient runtime dir so any
    # transient data lands in ${RUNTIME_DIR} (tmpfs). RuntimeDirectory creates it
    # (owned by the service user) before ExecStart.
    info "Working directory (transient data): ${RUNTIME_DIR}"
    $SUDO install -d -m 0755 "$(dirname "$DETECT_DROPIN")"
    $SUDO tee "$DETECT_DROPIN" >/dev/null <<EOF
# Managed by install.sh — run from the transient runtime dir.
[Service]
RuntimeDirectory=rockfish
RuntimeDirectoryPreserve=yes
WorkingDirectory=${RUNTIME_DIR}
EOF

    # Report service drop-in: pin the cadence AND run from the same runtime dir.
    info "Report cadence: every ${REPORT_INTERVAL_MIN} min"
    $SUDO install -d -m 0755 "$(dirname "$REPORT_DROPIN")"
    $SUDO tee "$REPORT_DROPIN" >/dev/null <<EOF
# Managed by install.sh — regenerate the report every ${REPORT_INTERVAL_MIN} minutes.
[Service]
ExecStart=
ExecStart=${BIN} --config ${PREFIX}/etc/rockfish.yaml --env-file ${PREFIX}/etc/rockfish.env report --continuous --serve --port 8080 --interval-minutes ${REPORT_INTERVAL_MIN}
RuntimeDirectory=rockfish
WorkingDirectory=${RUNTIME_DIR}
EOF

    $SUDO systemctl daemon-reload
    # enable = start on every boot (persistent); start = start right now.
    info "Enabling services on boot (persistent)…"
    $SUDO systemctl enable rockfish.service rockfish-report.service >/dev/null 2>&1 \
        || warn "could not enable one or both units (are they installed?)"
    # Start now, but don't abort the install if config/Suricata isn't ready yet.
    $SUDO systemctl start rockfish.service \
        || warn "rockfish.service didn't start — set up /opt/rockfish/etc/rockfish.yaml and Suricata, then: systemctl start rockfish"
    $SUDO systemctl start rockfish-report.service \
        || warn "rockfish-report.service didn't start — check config, then: systemctl start rockfish-report"
    SERVICES_ENABLED=1
    success "Services enabled on boot + started (detection + reporting every ${REPORT_INTERVAL_MIN} min)."
}

# Final actionable steps shown at the end of an APT install: drop in the license
# and (re)start the services so it takes effect.
post_install_reminder() {
    printf '\n'
    info "Final steps:"
    echo "  1. Place your license file at: ${LICENSE_FILE}"
    echo "     (or point '${PREFIX}/etc/rockfish.yaml' at it via 'license:', or pass --license <path>)"
    if [ "$SERVICES_ENABLED" = "1" ]; then
        echo "  2. Restart the services to load the license:"
        echo "       sudo systemctl restart rockfish rockfish-report"
    else
        echo "  2. Start the services once configured:"
        echo "       sudo systemctl enable --now rockfish rockfish-report"
    fi
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
                if [ "$u" = "rockfish-report" ] && [ -f "$REPORT_DROPIN" ]; then
                    pass "report cadence pinned to every ${REPORT_INTERVAL_MIN} min"
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
    [ -d "$DATA_STORE" ] && pass "parquet storage dir present: $DATA_STORE" || vwarn "parquet storage dir absent: $DATA_STORE"

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
    # Return non-zero if anything failed; callers decide how to react.
    [ "$FAIL_N" -eq 0 ]
}

# ── Install driver ───────────────────────────────────────────────────────
run_install() {
    info "Rockfish NDR installer"
    info "Platform: $OS/$ARCH${VERSION:+ | version: $VERSION}"

    choose_method
    case "$METHOD" in
        apt)
            info "Method: APT repository"
            install_apt
            # Install the matching libduckdb so the binary actually runs (the
            # .deb doesn't ship it).
            install_libduckdb
            # Default parquet storage under /opt/rockfish/data.
            setup_storage_dir
            # Optionally set up the systemd services (prompts unless overridden).
            if want_services; then enable_services; fi
            ;;
        docker)
            info "Method: Docker";  install_docker ;;
        *)
            error "Unknown ROCKFISH_METHOD='$METHOD' (expected 'apt' or 'docker')." ;;
    esac

    # Verify the result.
    printf '\n'
    info "Running post-install verification…"
    printf '\n'
    local vres=0
    run_verify || vres=1

    # Remind about the license + restart (APT installs).
    [ "$METHOD" = "apt" ] && post_install_reminder

    printf '\n'
    if [ "$vres" -eq 0 ]; then
        success "Done. Docs: https://docs.rockfishndr.com/getting-started/installation.html"
    else
        warn "Install completed, but verification reported issues above (e.g. libduckdb not yet present). Resolve them and re-run: install.sh verify"
        exit 1
    fi
}

usage() {
    cat <<EOF
Rockfish NDR installer

Usage:
  install.sh [install]     Install Rockfish NDR (default)
  install.sh verify        Run read-only diagnostics on an existing install
  install.sh help          Show this message

Environment:
  ROCKFISH_METHOD=apt|docker      Force the install method (default: auto-detect)
  ROCKFISH_VERSION=X.Y.Z          Pin a version (default: latest)
  ROCKFISH_IMAGE=...              Override the Docker image
  ROCKFISH_SERVICES=yes|no        Set up the systemd services without prompting
  ROCKFISH_REPORT_INTERVAL_MIN=N  Report cadence in minutes (default: 10)
  ROCKFISH_LIBDUCKDB_VERSION=X.Y.Z  Override the libduckdb version to install

Examples:
  curl -fsSL https://docs.rockfishndr.com/install.sh | bash
  curl -fsSL https://docs.rockfishndr.com/install.sh | bash -s -- verify
EOF
}

# ── Entry point ──────────────────────────────────────────────────────────
main() {
    case "${1:-install}" in
        install|"")      run_install ;;
        verify|--verify) run_verify || error "Installation incomplete — see FAIL items above." ;;
        help|-h|--help)  usage ;;
        *) error "Unknown command '$1' (expected: install | verify | help)." ;;
    esac
}

main "$@"
