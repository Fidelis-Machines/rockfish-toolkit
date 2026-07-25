#!/bin/bash
# Fidelis Farm & Technologies, LLC / Copyright 2025-2026
#
# Build script for the Rockfish TLS PQC Suricata plugin
# (per-handshake post-quantum key-exchange classification, NIST IR 8547).
#
# Usage:
#   ./build-pqc.sh              # Build the plugin
#   ./build-pqc.sh --test       # Run Rust unit tests only
#   ./build-pqc.sh --install    # Build and install to /usr/lib/suricata/plugins/
#   ./build-pqc.sh --clean      # Clean build artifacts

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

PLUGIN_DIR="$TOOLKIT_PROTO_PLUGINS_DIR/tls_pqc"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()    { echo -e "${BLUE}==>${NC} $1"; }
success() { echo -e "${GREEN}==>${NC} $1"; }
warn()    { echo -e "${YELLOW}Warning:${NC} $1"; }
error()   { echo -e "${RED}Error:${NC} $1" >&2; exit 1; }

DO_TEST=false
DO_INSTALL=false
DO_CLEAN=false

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Build the Rockfish TLS PQC Suricata plugin.

Classifies each TLS flow's post-quantum key exchange and emits one 'pqc' EVE
event per flow with a NIST IR 8547 compliance verdict:
  client_supported_groups, server_chosen_group, nist_compliant, exposure_class

Options:
  --test          Run Rust unit tests only (no Suricata dependency)
  --install       Build and install to /usr/lib/suricata/plugins/
  --clean         Clean build artifacts
  -h, --help      Show this help message

Environment:
  SURICATA_SRC    Path to Suricata source tree (default: /development/suricata)

Examples:
  $(basename "$0")                              # Build the plugin
  $(basename "$0") --test                       # Run unit tests
  $(basename "$0") --install                    # Build and install
  SURICATA_SRC=/opt/suricata $(basename "$0")   # Build against custom Suricata

EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --test) DO_TEST=true; shift ;;
        --install) DO_INSTALL=true; shift ;;
        --clean) DO_CLEAN=true; shift ;;
        -h|--help) usage ;;
        *) error "Unknown option: $1" ;;
    esac
done

# Verify plugin directory exists
[ -d "$PLUGIN_DIR" ] || error "Plugin directory not found: $PLUGIN_DIR"

cd "$PLUGIN_DIR"

if [ "$DO_CLEAN" = true ]; then
    info "Cleaning build artifacts..."
    make clean 2>/dev/null || true
    success "Clean complete"
    exit 0
fi

if [ "$DO_TEST" = true ]; then
    info "Running Rust unit tests..."
    cargo test
    success "All tests passed"
    exit 0
fi

# Build the plugin
info "Building TLS PQC plugin..."

# Check for Suricata
if command -v libsuricata-config &>/dev/null; then
    info "  Suricata: $(libsuricata-config --version 2>/dev/null || echo 'installed')"
elif [ -d "${SURICATA_SRC:-/development/suricata}" ]; then
    SURICATA_DIR="${SURICATA_SRC:-/development/suricata}"
    info "  Suricata: source tree at $SURICATA_DIR"
    if [ ! -f "$SURICATA_DIR/src/autoconf.h" ]; then
        warn "$SURICATA_DIR/src/autoconf.h not found."
        warn "Run './configure' in the Suricata source tree first, e.g.:"
        warn "  (cd $SURICATA_DIR && ./autogen.sh && ./configure --enable-plugins && make)"
        info "Building Rust static library (compile-check only)..."
        cargo build --release
        warn "════════════════════════════════════════════════════════════"
        warn "  Built: target/release/libsuricata_tls_pqc.a"
        warn "  THIS IS NOT A SURICATA PLUGIN. It is a Rust static library"
        warn "  for compile-checking only. Suricata loads .so files; .a"
        warn "  files cannot be loaded at runtime."
        warn "  To produce a real .so, fix the toolchain above and rerun."
        warn "════════════════════════════════════════════════════════════"
        exit 1
    fi
else
    warn "Suricata not installed and no source tree found at /development/suricata."
    warn "Set SURICATA_SRC or install Suricata to build the .so plugin."
    info "Building Rust static library (compile-check only)..."
    cargo build --release
    warn "════════════════════════════════════════════════════════════"
    warn "  Built: target/release/libsuricata_tls_pqc.a"
    warn "  THIS IS NOT A SURICATA PLUGIN. It is a Rust static library"
    warn "  for compile-checking only. Suricata loads .so files; .a"
    warn "  files cannot be loaded at runtime."
    warn "  To produce a real .so, install Suricata and rerun."
    warn "════════════════════════════════════════════════════════════"
    exit 1
fi

make
success "Plugin built: rockfish-tls-pqc.so"

if [ "$DO_INSTALL" = true ]; then
    info "Installing plugin..."
    sudo make install
    success "Installed to /usr/lib/suricata/plugins/rockfish-tls-pqc.so"
    echo ""
    info "Add to suricata.yaml:"
    echo "  plugins:"
    echo "    - /usr/lib/suricata/plugins/rockfish-tls-pqc.so"
    echo ""
    echo "  outputs:"
    echo "    - eve-log:"
    echo "        types:"
    echo "          - pqc          # enable this plugin's output"
    echo ""
    echo "  rockfish-tls-pqc:"
    echo "    enabled: yes"
    echo "    tcp: yes"
    echo "    # See suricata-proto-plugins/tls_pqc/README.md for all options"
fi
