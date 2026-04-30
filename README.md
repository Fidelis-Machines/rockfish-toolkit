<p align="center">
  <img src="https://rockfishndr.com/rockfish-logo.png" alt="Rockfish NDR" width="320">
</p>

<h2 align="center">Rockfish Toolkit</h2>

## Description

Rockfish Toolkit is a toolkit of Suricata plugins and utilities — high-speed
packet capture, IIoT/OT protocol parsers, per-flow telemetry, and the build
scripts that tie them together. It powers the Rockfish NDR sensor's
detection pipeline.

## Components

### Capture plugin

| Plugin | Description |
|---|---|
| [`suricata-plugin-fmadio-ring/`](suricata-plugin-fmadio-ring/) | Zero-copy packet capture from FMADIO shared-memory ring buffers (`/opt/fmadio/queue/lxc_ring*`). One worker thread per ring. |

### Telemetry plugins

| Plugin | Emits | Description |
|---|---|---|
| [`suricata-proto-plugins/transport_perf/`](suricata-proto-plugins/transport_perf/) | `tcp_perf`, `udp_perf` | Per-flow TCP handshake RTT, retransmits, zero-windows, window stats; UDP request/response RTT and inter-arrival jitter. |
| [`suricata-proto-plugins/payload_entropy/`](suricata-proto-plugins/payload_entropy/) | `payload_entropy` | Per-flow Shannon entropy, PCR (producer/consumer ratio), and SPLT (Sequence of Packet Lengths and Times). |

### Protocol parsers (IIoT / OT / surveillance)

Application-layer parsers that decode binary protocols not covered by
Suricata's built-ins. Each emits its own EVE event type.

| Plugin | Protocol | Default port |
|---|---|---|
| [`asterix/`](suricata-proto-plugins/asterix/) | EUROCONTROL ASTERIX (radar / ADS-B surveillance) | UDP |
| [`bacnet/`](suricata-proto-plugins/bacnet/) | BACnet (building automation) | UDP 47808 |
| [`canopen/`](suricata-proto-plugins/canopen/) | CANopen (CAN-over-UDP) | UDP |
| [`coap/`](suricata-proto-plugins/coap/) | CoAP (constrained IoT) | UDP 5683 |
| [`enip/`](suricata-proto-plugins/enip/) | EtherNet/IP (CIP) | TCP/UDP 44818 / 2222 |
| [`ethercat/`](suricata-proto-plugins/ethercat/) | EtherCAT (industrial fieldbus) | L2 / UDP |
| [`iec104/`](suricata-proto-plugins/iec104/) | IEC 60870-5-104 (power/SCADA) | TCP 2404 |
| [`iec61850/`](suricata-proto-plugins/iec61850/) | IEC 61850 MMS (substation automation) | TCP 102 |
| [`lwm2m/`](suricata-proto-plugins/lwm2m/) | LwM2M (CoAP-based device mgmt) | UDP 5683 |
| [`opcua/`](suricata-proto-plugins/opcua/) | OPC UA (industrial telemetry) | TCP 4840 |
| [`profinet/`](suricata-proto-plugins/profinet/) | PROFINET DCP | UDP 34964 |
| [`s7comm/`](suricata-proto-plugins/s7comm/) | Siemens S7comm | TCP 102 |

> Suricata parses `enip`, `modbus`, `dnp3`, and `mqtt` natively — those EVE
> events feed Rockfish directly with no plugin needed. The `enip/` plugin
> here adds extended decoding beyond the built-in.

### Build scripts

All scripts live in [`scripts/`](scripts/) and must be run from inside the
`rockfish-toolkit` checkout (enforced by `_common.sh`).

| Script | Builds |
|---|---|
| [`scripts/build-plugins.sh`](scripts/build-plugins.sh) | All IIoT/OT protocol parsers (or a named subset). |
| [`scripts/build-perf.sh`](scripts/build-perf.sh) | `transport_perf` only. |
| [`scripts/build-entropy.sh`](scripts/build-entropy.sh) | `payload_entropy` only. |
| [`scripts/build-rtps.sh`](scripts/build-rtps.sh) | `rtps` parser only. |

The FMADIO ring plugin is built directly via its own `Makefile` (see
[its README](suricata-plugin-fmadio-ring/README.md)).

## Requirements

- Suricata 8.0+ (with plugin support enabled — `--enable-plugins`)
- Rust 1.70+ and Cargo
- GCC or Clang
- For the FMADIO ring plugin: access to `/opt/fmadio/queue/lxc_ring*`

## Building

Each plugin can be built standalone, or you can build them in batches
through the helper scripts.

### Build everything

```bash
# Protocol parsers (all of them)
./scripts/build-plugins.sh

# Telemetry plugins
./scripts/build-perf.sh
./scripts/build-entropy.sh

# FMADIO capture plugin
make -C suricata-plugin-fmadio-ring
```

### Build a subset

```bash
# Just OPC UA and S7comm
./scripts/build-plugins.sh opcua s7comm

# Run unit tests (no Suricata dependency)
./scripts/build-plugins.sh --test

# Clean
./scripts/build-plugins.sh --clean
```

### Build and install

```bash
# Protocol parsers → /opt/rockfish/plugins/  (override with PLUGIN_DIR_INSTALL)
./scripts/build-plugins.sh --install

# Telemetry plugins → /usr/lib/suricata/plugins/
./scripts/build-perf.sh    --install
./scripts/build-entropy.sh --install

# FMADIO capture plugin → /opt/suricata/lib/  (override with PLUGIN_DIR)
sudo make -C suricata-plugin-fmadio-ring install
```

### Build options

| Variable | Default | Used by |
|---|---|---|
| `SURICATA_SRC` | `/development/suricata` | All scripts — path to a configured Suricata source tree. Falls back to a Rust-only static-lib build if Suricata isn't found. |
| `PLUGIN_DIR_INSTALL` | `/opt/rockfish/plugins` | `build-plugins.sh --install` |
| `PLUGIN_DIR` | `/opt/suricata/lib` | FMADIO ring `make install` |
| `DUCKDB_LIB_DIR` | `/usr/local/lib` | Set by `_common.sh` for plugins that link DuckDB. |

If `libsuricata-config` is on `PATH`, it's used to discover include paths
automatically and `SURICATA_SRC` is ignored.

## Configuring Suricata

All plugins follow the same wiring pattern: load the `.so` under
`plugins:`, then enable the corresponding event type or app-layer
protocol. Telemetry events flow through Suricata's normal eve-log
pipeline — no second socket, no second file.

### Example `suricata.yaml`

```yaml
# 1. Load the plugin shared objects
plugins:
  # Capture (FMADIO ring)
  - /opt/suricata/lib/fmadio-ring.so

  # Telemetry
  - /usr/lib/suricata/plugins/rockfish-transport-perf.so
  - /usr/lib/suricata/plugins/rockfish-payload-entropy.so

  # Protocol parsers
  - /opt/rockfish/plugins/rockfish-opcua-parser.so
  - /opt/rockfish/plugins/rockfish-s7comm-parser.so
  - /opt/rockfish/plugins/rockfish-bacnet-parser.so
  - /opt/rockfish/plugins/rockfish-asterix-parser.so
  # ... add others as needed

# 2. Enable parsers under app-layer
app-layer:
  protocols:
    opcua:    { enabled: yes }
    s7comm:   { enabled: yes }
    bacnet:   { enabled: yes }
    asterix:  { enabled: yes }

# 3. Enable telemetry event types in eve-log
outputs:
  - eve-log:
      enabled: yes
      filetype: unix_stream
      filename: /var/run/rockfish/rockfish.sock
      types:
        - alert
        - flow
        - dns
        - tls: { extended: yes }
        - http
        # Telemetry plugin events
        - tcp_perf
        - udp_perf
        - payload_entropy
        # Protocol parser events
        - opcua
        - s7comm
        - bacnet
        - asterix

# 4. Per-plugin tuning (all keys optional — defaults shown)
rockfish-transport-perf:
  enabled: yes
  tcp: yes
  udp: yes
  sample-rate: 1
  max-flows: 100000

rockfish-payload-entropy:
  enabled: yes
  tcp: yes
  udp: yes
  sample-rate: 1
  max-bytes-per-direction: 8192
  emit:
    entropy: yes
    pcr: yes
    splt: yes

# 5. FMADIO ring capture (one entry per ring = one worker thread)
fmadio-ring:
  - ring: /opt/fmadio/queue/lxc_ring0
  - ring: /opt/fmadio/queue/lxc_ring1
```

### Running Suricata with the FMADIO capture plugin

```bash
suricata --capture-plugin fmadio-ring \
         -c /etc/suricata/suricata.yaml
```

Per-ring counters are exposed under `capture.fmadio_ringN.{packets,bytes,drops}`
and visible via `suricatasc -c "dump-counters" | grep fmadio`.

See each plugin's own README for the full set of tuning knobs, output
schemas, and example queries.

## Repository layout

```
rockfish-toolkit/
├── scripts/                       # Build helpers (build-plugins.sh, etc.)
├── suricata-plugin-fmadio-ring/   # FMADIO ring-buffer capture plugin
└── suricata-proto-plugins/
    ├── common/                    # Shared headers
    ├── transport_perf/            # tcp_perf / udp_perf telemetry
    ├── payload_entropy/           # entropy / PCR / SPLT telemetry
    ├── asterix/  bacnet/  canopen/  coap/  enip/  ethercat/
    ├── iec104/   iec61850/  lwm2m/  opcua/  profinet/  s7comm/
```

## License

GPL-2.0-only (matching Suricata).
