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
    rtps
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
PLUGIN_DESC[rtps]="RTPS/DDS/ROS 2 (UDP 7400+)"
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
  $(basename "$0") --test rtps coap    # Test specific plugins

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
FAILED_NAMES=()

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
        test_output=$(cd "$plugin_dir" && cargo test 2>&1)
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
        make_output=$(cd "$plugin_dir" && make 2>&1)
        make_rc=$?
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
        # Build Rust library only (no Suricata headers for .so linking)
        if (cd "$plugin_dir" && cargo build --release 2>&1 | tail -1); then
            success "  $plugin: built (Rust lib only)"
            PASSED=$((PASSED + 1))

            if [ "$DO_INSTALL" = true ]; then
                # Copy static lib for later linking
                lib_name="libsuricata_${plugin}_parser.a"
                lib_path="$plugin_dir/target/release/$lib_name"
                if [ -f "$lib_path" ]; then
                    sudo install -m 644 "$lib_path" "$INSTALL_DIR/"
                    info "  $plugin: installed $lib_name → $INSTALL_DIR/"
                fi
            fi
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
    echo -e "${GREEN}  Built: $PASSED${NC}, ${RED}Failed: $FAILED${NC}"
fi
echo "=============================================="

if [ ${#FAILED_NAMES[@]} -gt 0 ]; then
    echo ""
    echo -e "${RED}Failed plugins: ${FAILED_NAMES[*]}${NC}"
    exit 1
fi

if [ "$DO_INSTALL" = true ] && [ "$PASSED" -gt 0 ]; then
    echo ""
    info "Installed to: $INSTALL_DIR"
    ls -lh "$INSTALL_DIR"/ 2>/dev/null | grep -v "^total" | while read -r line; do
        echo "  $line"
    done

    # Show suricata.yaml config for .so plugins
    SO_COUNT=$(ls "$INSTALL_DIR"/rockfish-*.so 2>/dev/null | wc -l)
    if [ "$SO_COUNT" -gt 0 ]; then
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
    else
        echo ""
        info "Static libraries (.a) installed. To build .so plugins,"
        info "set SURICATA_SRC and rebuild:"
        echo "  SURICATA_SRC=/path/to/suricata ./scripts/build-plugins.sh --install"
    fi
fi
echo ""
