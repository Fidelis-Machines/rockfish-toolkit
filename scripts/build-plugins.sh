#!/bin/bash
# Fidelis Farm & Technologies, LLC / Copyright 2025-2026
#
# Build all Suricata IIoT/OT parser plugins
#
# Usage:
#   ./build-plugins.sh              # Build all plugins
#   ./build-plugins.sh --test       # Run all unit tests
#   ./build-plugins.sh --install    # Build and install all
#   ./build-plugins.sh --clean      # Clean all build artifacts
#   ./build-plugins.sh opcua s7comm # Build specific plugins only

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

PLUGINS_DIR="$TOOLKIT_PROTO_PLUGINS_DIR"
INSTALL_DIR="${PLUGIN_DIR_INSTALL:-/opt/rockfish/plugins}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

info()    { echo -e "${BLUE}==>${NC} $1"; }
success() { echo -e "${GREEN}==>${NC} $1"; }
warn()    { echo -e "${YELLOW}Warning:${NC} $1"; }
error()   { echo -e "${RED}Error:${NC} $1" >&2; exit 1; }
step()    { echo -e "${CYAN}───${NC} $1"; }

# All available plugins in priority order.
# NOTE: enip, modbus, dnp3, and mqtt are parsed by Suricata natively —
# no plugin needed. Their EVE events feed directly into rockfish.
ALL_PLUGINS=(
    opcua
    bacnet
    s7comm
    profinet
    coap
    lwm2m
    asterix
    iec61850
    iec104
    ethercat
    canopen
)

# Plugin descriptions
declare -A PLUGIN_DESC
PLUGIN_DESC[opcua]="OPC UA (TCP 4840)"
# enip: Suricata built-in (ALPROTO_ENIP) — no plugin needed
PLUGIN_DESC[bacnet]="BACnet (UDP 47808)"
PLUGIN_DESC[s7comm]="Siemens S7comm (TCP 102)"
PLUGIN_DESC[profinet]="PROFINET DCP (UDP 34964)"
PLUGIN_DESC[coap]="CoAP (UDP 5683)"
PLUGIN_DESC[lwm2m]="LwM2M (CoAP-based)"
PLUGIN_DESC[asterix]="ASTERIX radar (UDP)"
PLUGIN_DESC[iec61850]="IEC 61850 MMS (TCP 102)"
PLUGIN_DESC[iec104]="IEC 60870-5-104 (TCP 2404)"
PLUGIN_DESC[ethercat]="EtherCAT (L2/UDP)"
PLUGIN_DESC[canopen]="CANopen (CAN-over-UDP)"

DO_TEST=false
DO_INSTALL=false
DO_CLEAN=false
SELECTED_PLUGINS=()

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] [PLUGIN...]

Build Suricata IIoT/OT parser plugins.

Options:
  --test          Run Rust unit tests only (no Suricata dependency)
  --install       Build and install to /usr/lib/suricata/plugins/
  --clean         Clean build artifacts
  --list          List available plugins
  -h, --help      Show this help message

Available Plugins:
$(for p in "${ALL_PLUGINS[@]}"; do printf "  %-14s %s\n" "$p" "${PLUGIN_DESC[$p]}"; done)

Examples:
  $(basename "$0")                     # Build all plugins
  $(basename "$0") --test              # Test all plugins
  $(basename "$0") opcua s7comm enip   # Build specific plugins
  $(basename "$0") --test opcua coap   # Test specific plugins

Environment:
  SURICATA_SRC        Path to Suricata source tree (default: /development/suricata)
  PLUGIN_DIR_INSTALL  Install directory (default: /opt/rockfish/plugins)

EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --test) DO_TEST=true; shift ;;
        --install) DO_INSTALL=true; shift ;;
        --clean) DO_CLEAN=true; shift ;;
        --list)
            echo "Available plugins:"
            for p in "${ALL_PLUGINS[@]}"; do
                printf "  %-14s %s\n" "$p" "${PLUGIN_DESC[$p]}"
            done
            exit 0
            ;;
        -h|--help) usage ;;
        -*)  error "Unknown option: $1" ;;
        *)   SELECTED_PLUGINS+=("$1"); shift ;;
    esac
done

# Default to all plugins if none specified
if [ ${#SELECTED_PLUGINS[@]} -eq 0 ]; then
    SELECTED_PLUGINS=("${ALL_PLUGINS[@]}")
fi

# Validate selected plugins
for p in "${SELECTED_PLUGINS[@]}"; do
    [ -d "$PLUGINS_DIR/$p" ] || error "Plugin not found: $p (no directory at $PLUGINS_DIR/$p)"
done

echo ""
echo "=============================================="
echo "  Suricata IIoT/OT Parser Plugins"
echo "  ${#SELECTED_PLUGINS[@]} plugin(s) selected"
echo "=============================================="
echo ""

# Create install directory upfront if installing
if [ "$DO_INSTALL" = true ]; then
    sudo mkdir -p "$INSTALL_DIR"
    info "Install directory: $INSTALL_DIR"
fi

PASSED=0
FAILED=0
RUST_ONLY=0
FAILED_NAMES=()
RUST_ONLY_NAMES=()

for plugin in "${SELECTED_PLUGINS[@]}"; do
    plugin_dir="$PLUGINS_DIR/$plugin"
    desc="${PLUGIN_DESC[$plugin]:-$plugin}"

    if [ "$DO_CLEAN" = true ]; then
        step "Cleaning $plugin..."
        (cd "$plugin_dir" && cargo clean 2>/dev/null && rm -f *.so *.o *_ffi.h) || true
        continue
    fi

    if [ "$DO_TEST" = true ]; then
        step "Testing $plugin ($desc)..."
        test_output=$(cd "$plugin_dir" && cargo test 2>&1) || true
        test_line=$(echo "$test_output" | grep "test result:" | head -1)
        if echo "$test_line" | grep -q "0 failed"; then
            success "  $plugin: $test_line"
            PASSED=$((PASSED + 1))
        else
            echo -e "  ${RED}FAILED${NC}: $plugin"
            echo "$test_output" | tail -10
            FAILED=$((FAILED + 1))
            FAILED_NAMES+=("$plugin")
        fi
        continue
    fi

    # Build
    step "Building $plugin ($desc)..."

    # Check for Suricata
    HAS_SURICATA=false
    if command -v libsuricata-config &>/dev/null; then
        HAS_SURICATA=true
    elif [ -d "${SURICATA_SRC:-/development/suricata}" ]; then
        HAS_SURICATA=true
    fi

    if [ "$HAS_SURICATA" = true ]; then
        # Capture rc inline so a make failure doesn't trip `set -e` before
        # the error-handling branch below runs.
        make_output=$(cd "$plugin_dir" && make 2>&1) && make_rc=0 || make_rc=$?
        echo "$make_output" | tail -3
        if [ $make_rc -eq 0 ]; then
            success "  $plugin: built (.so)"
            PASSED=$((PASSED + 1))

            if [ "$DO_INSTALL" = true ]; then
                sudo install -m 755 "$plugin_dir"/rockfish-*-parser.so "$INSTALL_DIR/" 2>/dev/null || \
                sudo install -m 755 "$plugin_dir"/*.so "$INSTALL_DIR/" 2>/dev/null
                info "  $plugin: installed → $INSTALL_DIR/"
            fi
        else
            echo -e "  ${RED}FAILED${NC}: $plugin"
            FAILED=$((FAILED + 1))
            FAILED_NAMES+=("$plugin")
        fi
    else
        # Suricata headers absent — fall back to a compile-check of the
        # Rust crate. NOTE: the resulting .a is NOT a Suricata plugin and
        # cannot be installed/loaded; we never copy it to INSTALL_DIR.
        if (cd "$plugin_dir" && cargo build --release 2>&1 | tail -1); then
            warn "  $plugin: Rust compile-check only — NOT a .so plugin (.a not loadable)"
            RUST_ONLY=$((RUST_ONLY + 1))
            RUST_ONLY_NAMES+=("$plugin")
        else
            echo -e "  ${RED}FAILED${NC}: $plugin"
            FAILED=$((FAILED + 1))
            FAILED_NAMES+=("$plugin")
        fi
    fi
done

echo ""
echo "=============================================="
if [ "$DO_CLEAN" = true ]; then
    echo -e "${GREEN}  Clean complete${NC}"
elif [ "$DO_TEST" = true ]; then
    echo -e "${GREEN}  Tests: $PASSED passed${NC}, ${RED}$FAILED failed${NC}"
else
    echo -e "${GREEN}  Built (.so): $PASSED${NC}, ${YELLOW}Rust-only (not installable): $RUST_ONLY${NC}, ${RED}Failed: $FAILED${NC}"
fi
echo "=============================================="

if [ ${#FAILED_NAMES[@]} -gt 0 ]; then
    echo ""
    echo -e "${RED}Failed plugins: ${FAILED_NAMES[*]}${NC}"
fi

if [ ${#RUST_ONLY_NAMES[@]} -gt 0 ]; then
    echo ""
    warn "════════════════════════════════════════════════════════════"
    warn "  Plugins compiled as Rust .a only (NOT Suricata plugins):"
    warn "    ${RUST_ONLY_NAMES[*]}"
    warn "  Suricata loads .so files, not .a. To produce loadable plugins,"
    warn "  install Suricata's plugin headers (libsuricata-config on PATH)"
    warn "  or build the source tree at \$SURICATA_SRC, then rerun this"
    warn "  script. The .a artifacts have NOT been installed."
    warn "════════════════════════════════════════════════════════════"
fi

# Treat Rust-only and explicit failures as a non-zero exit so callers
# (and CI) can detect that no usable plugin was produced.
if [ "$FAILED" -gt 0 ] || [ "$RUST_ONLY" -gt 0 ]; then
    exit 1
fi

if [ "$DO_INSTALL" = true ] && [ "$PASSED" -gt 0 ]; then
    echo ""
    info "Installed to: $INSTALL_DIR"
    ls -lh "$INSTALL_DIR"/ 2>/dev/null | grep -v "^total" | while read -r line; do
        echo "  $line"
    done

    # All entries here are .so by construction (the .a fallback never installs).
    echo ""
    info "Add to suricata.yaml:"
    echo ""
    echo "  plugins:"
    for plugin in "${SELECTED_PLUGINS[@]}"; do
        so_file="$INSTALL_DIR/rockfish-${plugin}-parser.so"
        if [ -f "$so_file" ]; then
            echo "    - $so_file"
        fi
    done
    echo ""
    echo "  app-layer:"
    echo "    protocols:"
    for plugin in "${SELECTED_PLUGINS[@]}"; do
        so_file="$INSTALL_DIR/rockfish-${plugin}-parser.so"
        if [ -f "$so_file" ]; then
            echo "      ${plugin}:"
            echo "        enabled: yes"
        fi
    done
fi
echo ""
