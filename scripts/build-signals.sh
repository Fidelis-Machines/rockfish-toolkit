#!/bin/bash
# Fidelis Farm & Technologies, LLC / Copyright 2025-2026
#
# Build script for the Rockfish Transport Signals Suricata plugin
# (per-flow TCP/UDP RTT, retransmits, zero-windows, jitter).
#
# Usage:
#   ./build-signals.sh              # Build the plugin
#   ./build-signals.sh --test       # Run Rust unit tests only
#   ./build-signals.sh --install    # Build and install to /usr/lib/suricata/plugins/
#   ./build-signals.sh --clean      # Clean build artifacts

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

PLUGIN_DIR="$TOOLKIT_PROTO_PLUGINS_DIR/transport_signals"

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

Build the Rockfish Transport Signals Suricata plugin.

Captures per-flow TCP/UDP signals not exposed by the standard EVE flow event:
  TCP: handshake RTT, retransmits, out-of-order, zero-window, window stats
  UDP: request/response RTT, inter-arrival jitter, per-direction stats

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
info "Building Transport Signals plugin..."

# Check for Suricata
if command -v libsuricata-config &>/dev/null; then
    info "  Suricata: $(libsuricata-config --version 2>/dev/null || echo 'installed')"
elif [ -d "${SURICATA_SRC:-/development/suricata}" ]; then
    SURICATA_DIR="${SURICATA_SRC:-/development/suricata}"
    info "  Suricata: source tree at $SURICATA_DIR"
    if [ ! -f "$SURICATA_DIR/src/autoconf.h" ]; then
        warn "$SURICATA_DIR/src/autoconf.h not found."
        warn "Run './configure' in the Suricata source tree first, e.g.:"
        warn "  (cd $SURICATA_DIR && ./autogen.sh && ./configure)"
        warn "Falling back to Rust-only build."
        info "Building Rust static library..."
        cargo build --release
        success "Rust library built: target/release/libsuricata_transport_signals.a"
        exit 0
    fi
else
    warn "Suricata source not found. Building Rust library only."
    warn "Set SURICATA_SRC or install Suricata to build the full .so plugin."
    info "Building Rust static library..."
    cargo build --release
    success "Rust library built: target/release/libsuricata_transport_signals.a"
    exit 0
fi

make
success "Plugin built: rockfish-transport-signals.so"

if [ "$DO_INSTALL" = true ]; then
    info "Installing plugin..."
    sudo make install
    success "Installed to /usr/lib/suricata/plugins/rockfish-transport-signals.so"
    echo ""
    info "Add to suricata.yaml:"
    echo "  plugins:"
    echo "    - /usr/lib/suricata/plugins/rockfish-transport-signals.so"
    echo ""
    echo "  rockfish-transport-signals:"
    echo "    enabled: yes"
    echo "    tcp: yes"
    echo "    udp: yes"
    echo "    # See suricata-proto-plugins/transport_signals/README.md for all options"
fi
