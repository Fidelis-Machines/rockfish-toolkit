<p align="center">
  <a href="https://rockfishndr.com" title="Rockfish NDR — learn more"><img src="https://rockfishndr.com/rockfish-logo.png" alt="Rockfish NDR" width="320"></a>
</p>

<h2 align="center">Rockfish Toolkit</h2>

<p align="center">
  <a href="https://docs.rockfishndr.com/">Documentation</a> &middot;
  <a href="https://github.com/Fidelis-Machines/rockfish-toolkit/issues">Issues</a>
</p>

## Description

Rockfish Toolkit is a collection of Suricata plugins and utilities — high-speed packet capture, IIoT/OT protocol parsers, per-flow transport signals, and the build scripts that tie them together. It powers the Rockfish NDR sensor's detection pipeline and grows with each phase of Fidelis Machines' research in ROS / OT / IoT security.

> **Learn more about Rockfish NDR** — the air-gap-native Network Detection &amp; Response solution built with this toolkit: <https://rockfishndr.com>


## Get the code

```bash
git clone https://github.com/Fidelis-Machines/rockfish-toolkit.git
cd rockfish-toolkit
```

Browse the source on GitHub: <https://github.com/Fidelis-Machines/rockfish-toolkit>

## Components

### Capture plugin

| Plugin | Description |
|---|---|
| [`suricata-plugin-fmadio-ring/`](suricata-plugin-fmadio-ring/) | Zero-copy packet capture from FMADIO shared-memory ring buffers (`/opt/fmadio/queue/lxc_ring*`). One worker thread per ring. |

### Telemetry plugins

| Plugin | Emits | Description |
|---|---|---|
| [`suricata-proto-plugins/transport_signals/`](suricata-proto-plugins/transport_signals/) | `tcp_signals`, `udp_signals` | Per-flow TCP handshake RTT, retransmits, zero-windows, window stats; UDP request/response RTT and inter-arrival jitter. Downstream consumers derive odometry from these. |
| [`suricata-proto-plugins/payload_entropy/`](suricata-proto-plugins/payload_entropy/) | `payload_entropy` | Per-flow Shannon entropy, PCR (producer/consumer ratio), and SPLT (Sequence of Packet Lengths and Times). |

### Protocol parsers (industrial protocols)

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
| [`scripts/build-signals.sh`](scripts/build-signals.sh) | `transport_signals` only. |
| [`scripts/build-entropy.sh`](scripts/build-entropy.sh) | `payload_entropy` only. |
| [`scripts/build-rtps.sh`](scripts/build-rtps.sh) | `rtps` parser only. |

The FMADIO ring plugin is built directly via its own `Makefile` (see
[its README](suricata-plugin-fmadio-ring/README.md)).

## Telemetry Plugins in Detail

The two telemetry plugins are the analytics workhorses of the toolkit —
they don't decode application protocols, they compute per-flow signals
that downstream detection engines (HBOS, SIGMA) consume.

### `transport_signals` — Network signal metrics

A Suricata plugin that emits **`tcp_signals`** and **`udp_signals`**
events alongside Suricata's normal flow records. It tracks the per-flow
signals you'd normally need a separate APM agent for — handshake
latency, retransmits, application-level RTT, jitter, DNS health —
without touching the application stack. Downstream consumers turn these
into odometry (relative, incremental measurements anchored to the flow's
first observation) by joining on `flow_id`.

**TCP metrics** (emitted as `tcp_signals` events, one per flow):

| Field | Meaning |
|---|---|
| `handshake_rtt_us` | SYN-to-ACK time on the three-way handshake |
| `ttfb_us` | Time-to-first-byte from handshake completion to first server payload |
| `retransmits_toserver` / `_toclient` | Detected duplicate-sequence counts in each direction |
| `zero_windows_toserver` / `_toclient` | Receive-window-exhaustion events |
| `rst_toserver` / `_toclient` | RST close counts (vs. clean FIN) |
| `state` | Derived health: `ok`, `drift`, `sla_breach`, `critical` |

**UDP metrics** (emitted as `udp_signals` events):

| Field | Meaning |
|---|---|
| `request_response_rtt_us` | Time between matched request / response pairs (DNS, RADIUS, NTP, SIP, etc.) |
| `inter_arrival_jitter_us` | Variance of packet inter-arrival times |
| `packet_loss_proxy` | Gap heuristic for sequenced UDP (RTP, QUIC) |
| DNS-specific | Query duration, NXDOMAIN rate, response-code distribution |

**Configuration** (`rockfish-transport-signals:` block in `suricata.yaml`):

| Key | Default | Description |
|---|---|---|
| `enabled` | `yes` | Master toggle |
| `tcp` | `yes` | Track TCP flows |
| `udp` | `yes` | Track UDP flows |
| `sample-rate` | `1` | Emit every Nth flow (1 = every flow) |
| `max-flows` | `100000` | Memory cap on the in-flight flow table |

**What it catches** — congested links, brownouts before users notice
them (handshake-latency drift), failing peers (rising retransmits),
capacity issues (zero-window saturation), zombie connections (high RST
rate), DNS problems (slow lookups, NXDOMAIN spikes). Surfaces in the
Rockfish NDR **Performance** report page and SLA dashboards.

### `payload_entropy` — Encrypted Traffic Analysis

A Suricata plugin emitting **`payload_entropy`** events. Implements
a feature set similar to Cisco's ETA (Encrypted Traffic Analytics), letting you
fingerprint traffic that's already inside TLS/QUIC without breaking
encryption — finds C2 beacons, exfiltration tunnels, and custom-protocol
covert channels by their **shape**, not their content.

Metrics are computed during a capped sample window (default first 8 KB
per direction) so the cost stays bounded on long-lived flows.

**Per-direction Shannon entropy** — `entropy_toserver`,
`entropy_toclient` (bits/byte). Properly encrypted traffic sits at ~7.9;
structured / plaintext payloads fall below 6; tunneled binary embedded
inside an encrypted-looking wrapper is recognizable here.

**PCR (Producer / Consumer Ratio)** — `pcr ∈ [0..1] =
bytes_toserver / (bytes_toserver + bytes_toclient)`. Conversation shape
in one number:
- `pcr ≈ 0.05` → client-receives (download, browsing)
- `pcr ≈ 0.50` → symmetric (interactive)
- `pcr ≈ 0.85+` → client-sends (upload, **exfil candidate**)

**SPLT — Sequence of Packet Lengths and Times** in three forms:
- `splt_lengths` — `Vec<u16>` of raw payload lengths (first N packets)
- `splt_iats_us` — `Vec<u32>` of inter-arrival times in microseconds
- `splt` — letter-encoded summary string. Each packet becomes a letter
  where **case marks direction** (uppercase = toserver, lowercase =
  toclient) and the letter `A..K` / `a..k` is the log₂ size bucket
  from `<32 B` to `≥1024 B`. Easy to grep for patterns:
  - `AaAaAaAa` → regular small handshakes (likely beaconing)
  - `AaKKKKKK` → small request, bulk transfer
  - `KkKkKkKk` → balanced bulk

**Sample-window byte counts** — `bytes_sampled_toserver`,
`bytes_sampled_toclient` so consumers know how representative the
entropy reading is.

**Configuration** (`rockfish-payload-entropy:` block):

| Key | Default | Description |
|---|---|---|
| `enabled` | `yes` | Master toggle |
| `tcp` | `yes` | Sample TCP flows |
| `udp` | `yes` | Sample UDP flows |
| `sample-rate` | `1` | Emit every Nth flow |
| `max-bytes-per-direction` | `8192` | Bytes inspected per direction (memory bound) |
| `emit.entropy` | `yes` | Emit entropy fields |
| `emit.pcr` | `yes` | Emit PCR field |
| `emit.splt` | `yes` | Emit SPLT fields (heaviest payload — disable to shrink event size) |

**What it catches** — beaconing (regular SPLT pattern + `pcr ≈ 0.5`
over many short flows), exfiltration (high PCR + elevated entropy
outbound), tunneling (entropy mismatch with expected protocol — e.g.,
port 53 with `entropy_toserver = 7.8`), and C2 traffic that no signature
matches but whose SPLT shape is anomalous for the destination. Surfaces
in the Rockfish NDR **Encryption** report page: top encrypted talkers,
exfil candidates, beacons by SPLT, common-shape clusters, and
per-protocol entropy anomalies.

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
  - /usr/lib/suricata/plugins/rockfish-transport-signals.so
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
        - tcp_signals
        - udp_signals
        - payload_entropy
        # Protocol parser events
        - opcua
        - s7comm
        - bacnet
        - asterix

# 4. Per-plugin tuning (all keys optional — defaults shown)
rockfish-transport-signals:
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
    ├── transport_signals/         # tcp_signals / udp_signals telemetry
    ├── payload_entropy/           # entropy / PCR / SPLT telemetry
    ├── asterix/  bacnet/  canopen/  coap/  enip/  ethercat/
    ├── iec104/   iec61850/  lwm2m/  opcua/  profinet/  s7comm/
```

## License

GPL-2.0-only (matching Suricata).
