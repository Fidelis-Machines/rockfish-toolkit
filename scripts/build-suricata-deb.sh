#!/bin/bash
# Fidelis Farm & Technologies, LLC / Copyright 2025-2026
# SPDX-License-Identifier: LicenseRef-Rockfish-Commercial
#
# build-suricata-deb.sh — Build a "Rockfish Suricata" .deb
#
# Builds upstream Suricata from source with the Rockfish Suricata plugins baked
# in (FMADIO capture, OT/IIoT protocol decoders, and the transport_signals /
# payload_entropy (ETA) / tls_pqc telemetry plugins), plus a Rockfish-wired
# suricata.yaml and a systemd unit — packaged as a single self-contained .deb
# installed under /opt/rockfish-suricata.
#
# The whole build runs inside a debian:bookworm container so the binary and
# plugins link against the older glibc (2.36) and run on bookworm and newer —
# the same reproducibility contract as the engine's build-deb.sh.
#
# Usage:
#   ./build-suricata-deb.sh                        # Suricata 8.0.6, all plugins
#   SURICATA_VERSION=8.0.6 ./build-suricata-deb.sh # pin a version
#   ./build-suricata-deb.sh --deb-rev 2            # bump the packaging revision
#   ./build-suricata-deb.sh --plugins "transport_signals payload_entropy tls_pqc"
#   ./build-suricata-deb.sh --output /path/to/pool
#
# Requires: docker.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
source "$SCRIPT_DIR/_common.sh"

# ── Colors ───────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()    { echo -e "${BLUE}==>${NC} $1"; }
success() { echo -e "${GREEN}==>${NC} $1"; }
warn()    { echo -e "${YELLOW}Warning:${NC} $1"; }
error()   { echo -e "${RED}Error:${NC} $1" >&2; exit 1; }

# ── Parameters ───────────────────────────────────────────────────────────
SURICATA_VERSION="${SURICATA_VERSION:-8.0.6}"     # upstream stable to build
DEB_REV="${DEB_REV:-1}"                            # packaging revision
PKG_ARCH="${ROCKFISH_ARCH:-amd64}"
PREFIX="/opt/rockfish-suricata"                    # self-contained install root
EVE_SOCKET="/var/run/rockfish/rockfish.sock"       # Rockfish EVE input socket
OUTPUT_DIR="$TOOLKIT_DIR/dist"
PUBLISH=false
# All Rockfish plugins. OT decoders + telemetry + FMADIO capture. (enip/modbus/
# dnp3/mqtt are parsed by Suricata natively; enip here adds extended decoding.)
PLUGINS="fmadio-ring transport_signals payload_entropy tls_pqc \
opcua bacnet s7comm profinet coap lwm2m asterix iec61850 iec104 ethercat canopen enip"

usage() {
    sed -n '5,27p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
}
while [[ $# -gt 0 ]]; do
    case "$1" in
        --suricata-version) SURICATA_VERSION="$2"; shift 2 ;;
        --deb-rev)          DEB_REV="$2"; shift 2 ;;
        --arch)             PKG_ARCH="$2"; shift 2 ;;
        --plugins)          PLUGINS="$2"; shift 2 ;;
        --output)           OUTPUT_DIR="$2"; shift 2 ;;
        --publish)          PUBLISH=true; shift ;;
        -h|--help)          usage ;;
        *) error "Unknown option: $1" ;;
    esac
done

command -v docker &>/dev/null || error "docker not found (needed for the glibc-compatible build)."
[ "$PKG_ARCH" = "amd64" ] || warn "Only amd64 is validated; '$PKG_ARCH' is best-effort."

PKG_VERSION="${SURICATA_VERSION}-rockfish${DEB_REV}"
PKG_FULL="rockfish-suricata_${PKG_VERSION}_${PKG_ARCH}"
mkdir -p "$OUTPUT_DIR"

info "Building Rockfish Suricata ${SURICATA_VERSION} (.deb ${PKG_VERSION}, plugins: ${PLUGINS})"

# The container gets the whole toolkit (for the plugin sources) read-only, plus
# a writable staging dir where it assembles the package tree, then dpkg-deb.
docker run --rm \
    -v "$TOOLKIT_DIR":/toolkit:ro \
    -v "$OUTPUT_DIR":/out \
    -e SURICATA_VERSION="$SURICATA_VERSION" \
    -e PKG_VERSION="$PKG_VERSION" \
    -e PKG_ARCH="$PKG_ARCH" \
    -e PREFIX="$PREFIX" \
    -e EVE_SOCKET="$EVE_SOCKET" \
    -e PLUGINS="$PLUGINS" \
    -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
    rust:1-bookworm bash -euxc '
        export DEBIAN_FRONTEND=noninteractive
        # Base image is rust:1-bookworm — recent rustup Rust (Suricata 8 needs
        # >= 1.75; the distro rustc is too old) on bookworm glibc (2.36), the same
        # reproducibility contract as build-deb.sh. Do NOT apt-install rustc/cargo
        # (that would shadow rustup with the old 1.63 package).
        apt-get update
        apt-get install -y --no-install-recommends \
            build-essential cmake make pkg-config wget ca-certificates file \
            libpcre2-dev libyaml-dev libjansson-dev libmagic-dev libcap-ng-dev \
            libpcap-dev zlib1g-dev liblz4-dev libnet1-dev libnetfilter-queue-dev \
            libnfnetlink-dev libunwind-dev python3 dpkg-dev
        rustc --version; cargo --version

        # ── 1. Suricata from source ──────────────────────────────────────
        cd /build 2>/dev/null || { mkdir -p /build && cd /build; }
        wget -q "https://www.openinfosecfoundation.org/download/suricata-${SURICATA_VERSION}.tar.gz"
        tar xzf "suricata-${SURICATA_VERSION}.tar.gz"
        SRC="/build/suricata-${SURICATA_VERSION}"
        cd "$SRC"
        ./configure --prefix="$PREFIX" --sysconfdir="$PREFIX/etc" \
            --localstatedir=/var --disable-gccmarch-native
        make -j"$(nproc)"

        # Stage the package tree.
        PKG=/build/pkg
        rm -rf "$PKG"; mkdir -p "$PKG"
        make install DESTDIR="$PKG"
        make install-conf DESTDIR="$PKG" || true   # default suricata.yaml + rules dirs

        # ── 2. Rockfish plugins (built against this Suricata source) ─────
        PLUGDIR="$PKG$PREFIX/lib/rockfish-plugins"
        mkdir -p "$PLUGDIR"
        built=""; failed=""
        for p in $PLUGINS; do
            # Locate the plugin source dir in the toolkit layout.
            if [ "$p" = "fmadio-ring" ]; then
                d="/toolkit/suricata-plugin-fmadio-ring"
            else
                d="/toolkit/suricata-proto-plugins/$p"
            fi
            if [ ! -d "$d" ]; then
                echo "  SKIP $p (no source at $d)"; failed="$failed $p"; continue
            fi
            # Build in a writable copy (toolkit is mounted read-only).
            work="/build/plug/$p"; mkdir -p "$work"; cp -a "$d/." "$work/"
            if (cd "$work" && make SURICATA_SRC="$SRC" >/tmp/mk.$p.log 2>&1); then
                # collect any .so the make produced
                find "$work" -maxdepth 1 -name "*.so" -exec cp {} "$PLUGDIR/" \;
                echo "  built plugin: $p"; built="$built $p"
            else
                echo "  FAILED plugin: $p (see below)"; tail -15 /tmp/mk.$p.log || true
                failed="$failed $p"
            fi
        done
        echo "PLUGINS built:$built"
        echo "PLUGINS failed:$failed"

        # ── 3. Rockfish-wired suricata.yaml ──────────────────────────────
        # Start from Suricata'\''s installed default and patch: load the Rockfish
        # plugins, and send EVE to the Rockfish unix_stream socket.
        CONF="$PKG$PREFIX/etc/suricata/suricata.yaml"
        [ -f "$CONF" ] || CONF="$PKG$PREFIX/etc/suricata.yaml"
        if [ -f "$CONF" ]; then
            {
              echo ""
              echo "# ── Rockfish plugins (auto-added by build-suricata-deb.sh) ──"
              echo "plugins:"
              for so in "$PLUGDIR"/*.so; do [ -e "$so" ] && echo "  - $PREFIX/lib/rockfish-plugins/$(basename "$so")"; done
            } >> "$CONF"
            # Point the default eve-log at the Rockfish socket (unix_stream).
            sed -i -E "s#(filetype:\s*)regular#\1unix_stream#; s#(filename:\s*)eve\.json#\1$EVE_SOCKET#" "$CONF" || true
        else
            echo "  (no default suricata.yaml found to patch)"
        fi

        # ── 4. systemd unit ──────────────────────────────────────────────
        mkdir -p "$PKG/lib/systemd/system"
        cat > "$PKG/lib/systemd/system/rockfish-suricata.service" <<UNIT
[Unit]
Description=Rockfish Suricata (Suricata ${SURICATA_VERSION} + Rockfish plugins)
Documentation=https://docs.rockfishndr.com/
After=network-online.target rockfish.service
Wants=network-online.target
# Rockfish creates the EVE socket; start it first so Suricata can connect.
After=rockfish.service

[Service]
Type=simple
# Join the rockfish group so Suricata can write the rockfish-owned EVE socket.
SupplementaryGroups=rockfish
ExecStart=$PREFIX/bin/suricata -c $PREFIX/etc/suricata/suricata.yaml --af-packet
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

        # ── 5. DEBIAN control + postinst ─────────────────────────────────
        mkdir -p "$PKG/DEBIAN"
        INSTALLED_KB=$(du -sk "$PKG$PREFIX" | cut -f1)
        cat > "$PKG/DEBIAN/control" <<CTL
Package: rockfish-suricata
Version: ${PKG_VERSION}
Architecture: ${PKG_ARCH}
Maintainer: Fidelis Machines <support@rockfishndr.com>
Section: net
Priority: optional
Homepage: https://rockfishndr.com
Installed-Size: ${INSTALLED_KB}
Depends: libpcre2-8-0, libyaml-0-2, libjansson4, libmagic1, libcap-ng0, libpcap0.8, zlib1g, liblz4-1, libnet1
Description: Rockfish Suricata — Suricata ${SURICATA_VERSION} with Rockfish plugins
 Self-contained Suricata build with the Rockfish Suricata plugins baked in
 (FMADIO capture, OT/IIoT protocol decoders, and the transport_signals /
 payload_entropy / tls_pqc telemetry plugins), plus a Rockfish-wired
 suricata.yaml (EVE -> ${EVE_SOCKET}) and a systemd unit. Installed under
 ${PREFIX}; feeds Rockfish NDR over the EVE unix_stream socket.
CTL
        cat > "$PKG/DEBIAN/postinst" <<PINST
#!/bin/bash
set -e
# Refresh the linker cache (self-contained libs live under the prefix; the
# binary uses an rpath, but ldconfig keeps any shared libs discoverable).
ldconfig || true
systemctl daemon-reload || true
echo ""
echo "Rockfish Suricata installed to ${PREFIX}."
echo "  1. Edit ${PREFIX}/etc/suricata/suricata.yaml (set your capture interface)."
echo "  2. Ensure Rockfish is running (it creates ${EVE_SOCKET})."
echo "  3. sudo systemctl enable --now rockfish-suricata"
exit 0
PINST
        chmod 755 "$PKG/DEBIAN/postinst"

        # ── 6. Build the .deb ────────────────────────────────────────────
        DEB="/out/rockfish-suricata_${PKG_VERSION}_${PKG_ARCH}.deb"
        dpkg-deb --root-owner-group --build "$PKG" "$DEB"
        chown "$HOST_UID:$HOST_GID" "$DEB"
        echo "BUILT: $DEB"
        echo "SUMMARY plugins built:$built"
        echo "SUMMARY plugins failed:$failed"
    '

DEB_OUT="$OUTPUT_DIR/${PKG_FULL}.deb"
[ -f "$DEB_OUT" ] || error "Build did not produce $DEB_OUT"
success "Built: $DEB_OUT ($(du -h "$DEB_OUT" | cut -f1))"

if [ "$PUBLISH" = true ]; then
    warn "Publishing must run in the rockfish repo (apt pool + update-repo.sh + push rockfish_apt image)."
    warn "Copy $DEB_OUT into ndr/rockfish_apt/pool/main/r/rockfish-suricata/ and run the release steps."
fi

info "Next: install with  sudo dpkg -i $DEB_OUT  (or add it to the APT repo)."
